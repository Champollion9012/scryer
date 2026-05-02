"""
Code Similarity Search for Solidity Contracts.
Uses multi-layer approach: Normalization + GraphCodeBERT Embedding + ChromaDB.

Optimized version with:
- Modern ChromaDB PersistentClient API
- GraphCodeBERT for better code structure understanding
- Function-level chunking for large contracts
"""

from __future__ import annotations

import hashlib
import os
import re
import threading
from pathlib import Path
from typing import Any

from scryer_logging import get_logger

_log = get_logger(__name__)

# Lazy imports for optional dependencies. Indexing is sometimes driven from
# concurrent code (multi-threaded crawlers, web request handlers); guard the
# singletons with locks so we never load the model twice.
_model: Any = None
_model_lock = threading.Lock()
_chroma_client: Any = None
_chroma_lock = threading.Lock()


# ============================================================================
# Layer 1: Code Normalization
# ============================================================================

SOLIDITY_KEYWORDS = {
    "pragma",
    "solidity",
    "import",
    "contract",
    "library",
    "interface",
    "function",
    "modifier",
    "event",
    "error",
    "struct",
    "enum",
    "mapping",
    "public",
    "private",
    "internal",
    "external",
    "pure",
    "view",
    "payable",
    "virtual",
    "override",
    "abstract",
    "constant",
    "immutable",
    "indexed",
    "if",
    "else",
    "for",
    "while",
    "do",
    "break",
    "continue",
    "return",
    "try",
    "catch",
    "revert",
    "require",
    "assert",
    "emit",
    "new",
    "delete",
    "true",
    "false",
    "this",
    "super",
    "constructor",
    "fallback",
    "receive",
    "uint",
    "uint8",
    "uint16",
    "uint32",
    "uint64",
    "uint128",
    "uint256",
    "int",
    "int8",
    "int16",
    "int32",
    "int64",
    "int128",
    "int256",
    "address",
    "bool",
    "string",
    "bytes",
    "bytes32",
    "bytes4",
    "memory",
    "storage",
    "calldata",
    "assembly",
    "unchecked",
}


def normalize_solidity_code(code: str) -> str:
    """
    Normalize Solidity code for similarity comparison.
    Removes comments, normalizes whitespace, addresses, and numeric literals.
    """
    # Remove single-line comments
    code = re.sub(r"//.*$", "", code, flags=re.MULTILINE)

    # Remove multi-line comments
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)

    # Remove string literals (replace with placeholder)
    code = re.sub(r'"[^"]*"', '""', code)
    code = re.sub(r"'[^']*'", "''", code)

    # Normalize hex addresses (0x followed by 40 hex chars)
    code = re.sub(r"0x[a-fA-F0-9]{40}", "0xADDRESS", code)

    # Normalize other hex literals
    code = re.sub(r"0x[a-fA-F0-9]+", "0xHEX", code)

    # Normalize large numeric literals (keep small ones for structure)
    code = re.sub(r"\b\d{10,}\b", "NUM", code)

    # Normalize whitespace
    code = re.sub(r"\s+", " ", code)
    code = code.strip()

    return code


def normalize_with_var_rename(code: str) -> str:
    """
    Aggressive normalization: also rename identifiers to generic names.
    This catches clones with different variable names.
    """
    code = normalize_solidity_code(code)

    # Find all identifiers
    identifier_pattern = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b")

    var_map: dict[str, str] = {}
    counter = 0

    def replace_identifier(match: re.Match) -> str:
        nonlocal counter
        name = match.group(1)

        # Keep keywords and type names
        if name.lower() in SOLIDITY_KEYWORDS:
            return name

        # Keep common patterns
        if name in ("NUM", "HEX", "ADDRESS"):
            return name

        # Rename user-defined identifiers
        if name not in var_map:
            var_map[name] = f"v{counter}"
            counter += 1

        return var_map[name]

    normalized = identifier_pattern.sub(replace_identifier, code)
    return normalized


def compute_normalized_hash(code: str, aggressive: bool = False) -> str:
    """Compute hash of normalized code."""
    if aggressive:
        normalized = normalize_with_var_rename(code)
    else:
        normalized = normalize_solidity_code(code)
    return hashlib.sha256(normalized.encode()).hexdigest()


# ============================================================================
# Layer 1.5: Function-Level Chunking
# ============================================================================


def extract_functions(code: str) -> list[tuple[str, str]]:
    """
    Extract individual functions from Solidity code.
    Returns list of (function_name, function_code) tuples.
    """
    functions = []

    # Pattern to match function definitions
    func_pattern = re.compile(r"(function\s+(\w+)\s*\([^)]*\)[^{]*\{)", re.MULTILINE)

    matches = list(func_pattern.finditer(code))

    for i, match in enumerate(matches):
        func_name = match.group(2)
        start = match.start()

        # Find matching closing brace
        brace_count = 0
        end = start
        in_func = False

        for j, char in enumerate(code[start:], start=start):
            if char == "{":
                brace_count += 1
                in_func = True
            elif char == "}":
                brace_count -= 1
                if in_func and brace_count == 0:
                    end = j + 1
                    break

        if end > start:
            func_code = code[start:end]
            functions.append((func_name, func_code))

    return functions


def chunk_solidity_code(code: str, max_chars: int = 8000) -> list[str]:
    """
    Chunk Solidity code intelligently by function boundaries.
    Falls back to simple splitting if no functions found.
    """
    if len(code) <= max_chars:
        return [code]

    # Try to extract functions
    functions = extract_functions(code)

    if not functions:
        # No functions found, fall back to simple chunking
        chunks = []
        for i in range(0, len(code), max_chars):
            chunks.append(code[i : i + max_chars])
        return chunks

    # Group functions into chunks
    chunks = []
    current_chunk = []
    current_len = 0

    for func_name, func_code in functions:
        func_len = len(func_code)

        if current_len + func_len > max_chars and current_chunk:
            chunks.append("\n\n".join(current_chunk))
            current_chunk = []
            current_len = 0

        current_chunk.append(func_code)
        current_len += func_len

    if current_chunk:
        chunks.append("\n\n".join(current_chunk))

    return chunks if chunks else [code]


# ============================================================================
# Layer 2: Embedding Generation (GraphCodeBERT)
# ============================================================================

DEFAULT_MODEL = os.getenv("SIMILARITY_MODEL", "microsoft/graphcodebert-base")


def get_embedding_model(model_name: str = DEFAULT_MODEL, device: str = "auto"):
    """
    Load embedding model (lazy, cached).

    Args:
        model_name: HuggingFace model name (default: graphcodebert-base)
        device: 'cuda', 'cpu', or 'auto'
    """
    global _model

    if _model is not None:
        return _model

    with _model_lock:
        if _model is not None:
            return _model
        try:
            import torch
            from sentence_transformers import SentenceTransformer

            if device == "auto":
                device = "cuda" if torch.cuda.is_available() else "cpu"

            _log.info("Loading embedding model: %s on %s...", model_name, device)
            _model = SentenceTransformer(model_name, device=device)
            _log.info("Model loaded successfully.")
            return _model

        except ImportError:
            raise ImportError("sentence-transformers not installed. Run: pip install sentence-transformers")


def generate_embedding(code: str, model: Any = None) -> list[float]:
    """Generate embedding vector for code."""
    if model is None:
        model = get_embedding_model()

    # Normalize before embedding
    normalized = normalize_solidity_code(code)

    # Use function-level chunking for large code
    if len(normalized) > 8000:
        chunks = chunk_solidity_code(normalized, max_chars=8000)
        # Average embeddings from all chunks
        embeddings = []
        for chunk in chunks:
            emb = model.encode(chunk, convert_to_numpy=True)
            embeddings.append(emb)

        import numpy as np

        avg_embedding = np.mean(embeddings, axis=0)
        return avg_embedding.tolist()

    embedding = model.encode(normalized, convert_to_numpy=True)
    return embedding.tolist()


def generate_embeddings_batch(codes: list[str], model: Any = None) -> list[list[float]]:
    """Generate embeddings for multiple code snippets (batched for efficiency)."""
    if model is None:
        model = get_embedding_model()

    # Normalize and chunk
    all_chunks = []
    chunk_counts = []

    for code in codes:
        normalized = normalize_solidity_code(code)
        if len(normalized) > 8000:
            chunks = chunk_solidity_code(normalized, max_chars=8000)
        else:
            chunks = [normalized]
        all_chunks.extend(chunks)
        chunk_counts.append(len(chunks))

    # Batch encode all chunks
    all_embeddings = model.encode(all_chunks, convert_to_numpy=True, show_progress_bar=True)

    # Average embeddings for each code
    import numpy as np

    result = []
    idx = 0
    for count in chunk_counts:
        if count == 1:
            result.append(all_embeddings[idx].tolist())
        else:
            avg = np.mean(all_embeddings[idx : idx + count], axis=0)
            result.append(avg.tolist())
        idx += count

    return result


# ============================================================================
# Layer 3: Vector Storage & Search (ChromaDB - New API)
# ============================================================================


def get_chroma_client(persist_dir: str = ".similarity_db"):
    """Get or create ChromaDB client using new PersistentClient API."""
    global _chroma_client

    if _chroma_client is not None:
        return _chroma_client

    with _chroma_lock:
        if _chroma_client is not None:
            return _chroma_client
        try:
            import chromadb

            # Use new PersistentClient API (ChromaDB 0.4+)
            Path(persist_dir).mkdir(parents=True, exist_ok=True)
            _chroma_client = chromadb.PersistentClient(path=persist_dir)
            return _chroma_client

        except ImportError:
            raise ImportError("chromadb not installed. Run: pip install chromadb")


class SimilarityIndex:
    """
    Index for storing and searching similar contracts.
    Uses GraphCodeBERT embeddings and ChromaDB for fast similarity search.
    """

    def __init__(
        self,
        collection_name: str = "solidity_contracts",
        persist_dir: str = ".similarity_db",
        model_name: str = DEFAULT_MODEL,
        device: str = "auto",
    ):
        self.collection_name = collection_name
        self.persist_dir = persist_dir
        self.model_name = model_name
        self.device = device
        self._model = None
        self._collection = None

    @property
    def model(self):
        if self._model is None:
            self._model = get_embedding_model(self.model_name, self.device)
        return self._model

    @property
    def collection(self):
        if self._collection is None:
            client = get_chroma_client(self.persist_dir)
            self._collection = client.get_or_create_collection(
                name=self.collection_name, metadata={"hnsw:space": "cosine"}
            )
        return self._collection

    def add_contract(
        self,
        contract_id: str,
        code: str,
        metadata: dict | None = None,
    ) -> None:
        """Add a contract to the index."""
        embedding = generate_embedding(code, self.model)
        norm_hash = compute_normalized_hash(code)
        aggressive_hash = compute_normalized_hash(code, aggressive=True)

        meta = metadata or {}
        meta["normalized_hash"] = norm_hash
        meta["aggressive_hash"] = aggressive_hash
        meta["code_length"] = len(code)

        self.collection.upsert(
            ids=[contract_id],
            embeddings=[embedding],
            metadatas=[meta],
            documents=[code[:10000]],  # Store truncated code for reference
        )

    def add_contracts_batch(
        self,
        contracts: list[tuple[str, str, dict | None]],  # (id, code, metadata)
    ) -> None:
        """Add multiple contracts efficiently."""
        if not contracts:
            return

        ids = [c[0] for c in contracts]
        codes = [c[1] for c in contracts]
        metadatas = []

        for c in contracts:
            meta = c[2] or {}
            meta["normalized_hash"] = compute_normalized_hash(c[1])
            meta["aggressive_hash"] = compute_normalized_hash(c[1], aggressive=True)
            meta["code_length"] = len(c[1])
            metadatas.append(meta)

        embeddings = generate_embeddings_batch(codes, self.model)
        documents = [c[:10000] for c in codes]

        self.collection.upsert(
            ids=ids,
            embeddings=embeddings,
            metadatas=metadatas,
            documents=documents,
        )

    def find_similar(
        self,
        code: str,
        n_results: int = 10,
        min_similarity: float = 0.7,
    ) -> list[dict]:
        """
        Find contracts similar to the given code.

        Returns list of {id, similarity, metadata, document}
        """
        embedding = generate_embedding(code, self.model)

        results = self.collection.query(
            query_embeddings=[embedding],
            n_results=n_results,
            include=["metadatas", "documents", "distances"],
        )

        similar = []
        if results["distances"] and results["distances"][0]:
            for i, dist in enumerate(results["distances"][0]):
                # ChromaDB returns distance, convert to similarity
                similarity = 1 - dist  # For cosine distance

                if similarity >= min_similarity:
                    similar.append(
                        {
                            "id": results["ids"][0][i],
                            "similarity": round(similarity, 4),
                            "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
                            "document": results["documents"][0][i] if results["documents"] else None,
                        }
                    )

        return similar

    def find_exact_clones(self, code: str) -> list[str]:
        """Find exact structural clones (same normalized hash)."""
        aggressive_hash = compute_normalized_hash(code, aggressive=True)

        results = self.collection.get(
            where={"aggressive_hash": aggressive_hash},
            include=["metadatas"],
        )

        return results["ids"]

    def delete_contract(self, contract_id: str) -> None:
        """Delete a contract from the index."""
        try:
            self.collection.delete(ids=[contract_id])
        except Exception:
            pass

    def stats(self) -> dict:
        """Get index statistics."""
        return {
            "collection_name": self.collection_name,
            "total_contracts": self.collection.count(),
            "persist_dir": self.persist_dir,
            "model": self.model_name,
        }

    def exists(self, contract_id: str) -> bool:
        """Check if a contract already exists in the index."""
        try:
            results = self.collection.get(ids=[contract_id], include=[])
            return len(results["ids"]) > 0
        except Exception:
            return False

    def get_all_ids(self) -> set[str]:
        """Get all contract IDs in the index (for batch checking)."""
        try:
            # Get all IDs efficiently
            results = self.collection.get(include=[])
            return set(results["ids"])
        except Exception:
            return set()


# ============================================================================
# CLI Helper Functions
# ============================================================================


def index_directory(
    sources_dir: Path,
    index: SimilarityIndex | None = None,
    batch_size: int = 50,
    skip_existing: bool = True,
) -> SimilarityIndex:
    """Index all Solidity files in a directory.

    Args:
        sources_dir: Directory containing .sol files
        index: SimilarityIndex instance (created if None)
        batch_size: Number of contracts to index per batch
        skip_existing: If True, skip contracts already in the index
    """
    if index is None:
        index = SimilarityIndex()

    sol_files = list(sources_dir.rglob("*.sol"))
    _log.info("Found %d Solidity files...", len(sol_files))

    # Get existing IDs if skipping
    existing_ids = set()
    if skip_existing:
        _log.info("Checking for already indexed contracts...")
        existing_ids = index.get_all_ids()
        _log.info("  Found %d already indexed contracts", len(existing_ids))

    batch: list[tuple[str, str, dict]] = []
    indexed = 0
    skipped = 0

    for file_path in sol_files:
        try:
            contract_id = file_path.as_posix()

            # Skip if already exists
            if skip_existing and contract_id in existing_ids:
                skipped += 1
                continue

            code = file_path.read_text(encoding="utf-8", errors="replace")
            metadata = {
                "filename": file_path.name,
                "path": str(file_path),
            }
            batch.append((contract_id, code, metadata))

            if len(batch) >= batch_size:
                index.add_contracts_batch(batch)
                indexed += len(batch)
                _log.info("  Indexed %d contracts (skipped %d)...", indexed, skipped)
                batch = []

        except Exception as e:
            _log.warning("  Error indexing %s: %s", file_path, e)

    if batch:
        index.add_contracts_batch(batch)
        indexed += len(batch)
        _log.info("  Indexed %d contracts (skipped %d)...", indexed, skipped)

    _log.info("Indexing complete. Total: %s contracts", index.stats()["total_contracts"])
    return index


def search_similar_contracts(
    query_file: Path,
    index: SimilarityIndex | None = None,
    n_results: int = 10,
    min_similarity: float = 0.7,
) -> list[dict]:
    """Search for contracts similar to a given file."""
    if index is None:
        index = SimilarityIndex()

    code = query_file.read_text(encoding="utf-8", errors="replace")
    return index.find_similar(code, n_results=n_results, min_similarity=min_similarity)
