#!/usr/bin/env python3
"""
CLI tool for Solidity code similarity search.

Usage:
    # Index all contracts in a directory
    python similarity_cli.py index --sources-dir sources

    # Search for similar contracts
    python similarity_cli.py search --query contract.sol --min-similarity 0.8

    # Find exact clones
    python similarity_cli.py clones --query contract.sol
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from scryer_logging import get_logger
from similarity import (
    SimilarityIndex,
    index_directory,
    search_similar_contracts,
)

_log = get_logger(__name__)


def cmd_index(args: argparse.Namespace) -> int:
    """Index contracts from a directory."""
    sources_dir = Path(args.sources_dir)
    if not sources_dir.exists():
        _log.error("Directory not found: %s", sources_dir)
        return 1

    index = SimilarityIndex(
        persist_dir=args.db_path,
        model_name=args.model,
        device=args.device,
    )

    index_directory(sources_dir, index, batch_size=args.batch_size)

    stats = index.stats()
    print(f"\nIndex stats: {json.dumps(stats, indent=2)}")
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    """Search for similar contracts."""
    query_file = Path(args.query)
    if not query_file.exists():
        _log.error("File not found: %s", query_file)
        return 1

    index = SimilarityIndex(
        persist_dir=args.db_path,
        model_name=args.model,
        device=args.device,
    )

    results = search_similar_contracts(
        query_file,
        index,
        n_results=args.n_results,
        min_similarity=args.min_similarity,
    )

    if not results:
        print("No similar contracts found.")
        return 0

    print(f"\nFound {len(results)} similar contracts:\n")
    for i, r in enumerate(results, 1):
        print(f"{i}. [{r['similarity']:.1%}] {r['id']}")
        if r.get("metadata"):
            print(f"   Metadata: {r['metadata']}")

    if args.json:
        print(f"\n{json.dumps(results, indent=2)}")

    return 0


def cmd_clones(args: argparse.Namespace) -> int:
    """Find exact structural clones."""
    query_file = Path(args.query)
    if not query_file.exists():
        _log.error("File not found: %s", query_file)
        return 1

    index = SimilarityIndex(persist_dir=args.db_path)

    code = query_file.read_text(encoding="utf-8", errors="replace")
    clones = index.find_exact_clones(code)

    if not clones:
        print("No exact clones found.")
        return 0

    print(f"\nFound {len(clones)} exact clones:\n")
    for clone_id in clones:
        print(f"  - {clone_id}")

    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    """Show index statistics."""
    index = SimilarityIndex(persist_dir=args.db_path)
    stats = index.stats()
    print(json.dumps(stats, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Solidity Code Similarity Search",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--db-path", default=".similarity_db", help="ChromaDB persist directory")
    parser.add_argument("--model", default="microsoft/codebert-base", help="Embedding model name")
    parser.add_argument("--device", default="auto", choices=["auto", "cuda", "cpu"], help="Device for inference")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Index command
    p_index = subparsers.add_parser("index", help="Index contracts from a directory")
    p_index.add_argument("--sources-dir", required=True, help="Directory containing .sol files")
    p_index.add_argument("--batch-size", type=int, default=50, help="Batch size for indexing")
    p_index.set_defaults(func=cmd_index)

    # Search command
    p_search = subparsers.add_parser("search", help="Search for similar contracts")
    p_search.add_argument("--query", required=True, help="Query .sol file")
    p_search.add_argument("--n-results", type=int, default=10, help="Number of results")
    p_search.add_argument("--min-similarity", type=float, default=0.7, help="Minimum similarity (0-1)")
    p_search.add_argument("--json", action="store_true", help="Output as JSON")
    p_search.set_defaults(func=cmd_search)

    # Clones command
    p_clones = subparsers.add_parser("clones", help="Find exact structural clones")
    p_clones.add_argument("--query", required=True, help="Query .sol file")
    p_clones.set_defaults(func=cmd_clones)

    # Stats command
    p_stats = subparsers.add_parser("stats", help="Show index statistics")
    p_stats.set_defaults(func=cmd_stats)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
