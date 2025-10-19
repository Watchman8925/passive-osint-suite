#!/usr/bin/env python3
"""
Anonymity Grid CLI - Command-line interface for the anonymity grid system.
"""

import argparse
import json
import sys
import time

from anonymity_grid import (
    AnonymityGrid,
    GridNodeRole,
    QueryPriority,
    anonymous_query,
    initialize_anonymity_grid,
)


def cmd_start_node(args):
    """Start an anonymity grid node."""
    print("Starting anonymity grid node...")
    print(f"Node ID: {args.node_id or 'auto-generated'}")
    print(f"Role: {args.role}")

    try:
        role = GridNodeRole(args.role)
    except ValueError:
        print(f"Invalid role: {args.role}")
        print(f"Valid roles: {[r.value for r in GridNodeRole]}")
        return 1

    grid = AnonymityGrid(node_id=args.node_id, role=role)
    grid.start_grid_services()

    print(f"✓ Grid node started: {grid.node_id}")
    print(f"Capabilities: {', '.join(grid.capabilities)}")

    if args.interactive:
        print("\nEntering interactive mode. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
                if args.show_stats:
                    stats = grid.get_grid_statistics()
                    print(
                        f"\rQueries: {stats['stats']['queries_submitted']} | "
                        f"Processed: {stats['stats']['queries_processed']} | "
                        f"Active: {stats['active_queries']}",
                        end="",
                    )
        except KeyboardInterrupt:
            print("\nStopping grid node...")

    grid.stop_grid_services()
    print("Grid node stopped.")


def cmd_submit_query(args):
    """Submit a query to the anonymity grid."""
    print("Submitting anonymous query...")
    print(f"Operation: {args.operation}")
    print(f"Target: {args.target}")

    try:
        priority = (
            QueryPriority(args.priority) if args.priority else QueryPriority.NORMAL
        )
    except ValueError:
        print(f"Invalid priority: {args.priority}")
        print(f"Valid priorities: {[p.value for p in QueryPriority]}")
        return 1

    # Parse parameters if provided
    parameters = {}
    if args.parameters:
        try:
            parameters = json.loads(args.parameters)
        except json.JSONDecodeError:
            print("Invalid JSON parameters.")
            return 1

    # Initialize grid if needed
    initialize_anonymity_grid(role=GridNodeRole.CONSUMER)

    # Submit query
    start_time = time.time()
    result = anonymous_query(
        operation_type=args.operation,
        target=args.target,
        parameters=parameters,
        priority=priority,
        timeout=args.timeout,
    )

    execution_time = time.time() - start_time

    if result:
        print(f"\n✓ Query completed in {execution_time:.2f} seconds")
        print(f"Success: {result.success}")
        print(f"Executor: {result.executor_node}")

        if result.success:
            print(f"Result: {json.dumps(result.result_data, indent=2)}")
        else:
            print(f"Error: {result.error_message}")
    else:
        print(f"\n❌ Query timed out after {args.timeout} seconds")
        return 1


def cmd_batch_query(args):
    """Submit multiple queries from a file."""
    try:
        with open(args.file, "r") as f:
            queries = json.load(f)
    except Exception as e:
        print(f"Failed to load queries file: {e}")
        return 1

    if not isinstance(queries, list):
        print("Queries file must contain a JSON array of query objects.")
        return 1

    grid = initialize_anonymity_grid(role=GridNodeRole.CONSUMER)

    print(f"Submitting {len(queries)} queries...")

    submitted_queries = []
    for i, query_spec in enumerate(queries):
        try:
            query_id = grid.submit_query(
                operation_type=query_spec["operation_type"],
                target=query_spec["target"],
                parameters=query_spec.get("parameters", {}),
                priority=QueryPriority(query_spec.get("priority", 3)),
                anonymous=query_spec.get("anonymous", True),
            )
            submitted_queries.append((query_id, query_spec))
            print(f"  [{i + 1}/{len(queries)}] Submitted: {query_id}")
        except Exception as e:
            print(f"  [{i + 1}/{len(queries)}] Failed: {e}")

    # Wait for results
    print(f"\nWaiting for {len(submitted_queries)} results...")

    results = []
    for query_id, query_spec in submitted_queries:
        result = grid.get_query_result(query_id, timeout=args.timeout)
        if result:
            results.append(
                {
                    "query_id": query_id,
                    "query": query_spec,
                    "result": {
                        "success": result.success,
                        "data": result.result_data,
                        "error": result.error_message,
                        "execution_time": result.execution_time,
                        "executor": result.executor_node,
                    },
                }
            )
            status = "✓" if result.success else "❌"
            print(
                f"  {status} {query_id}: {query_spec['operation_type']} "
                f"on {query_spec['target']}"
            )
        else:
            print(f"  ⏱ {query_id}: Timed out")

    # Save results if requested
    if args.output:
        try:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\nResults saved to: {args.output}")
        except Exception as e:
            print(f"Failed to save results: {e}")

    # Summary
    successful = sum(1 for r in results if r["result"]["success"])
    print(f"\nSummary: {successful}/{len(results)} queries successful")


def cmd_node_stats(args):
    """Show node statistics."""
    grid = initialize_anonymity_grid()
    stats = grid.get_grid_statistics()

    print("Anonymity Grid Node Statistics")
    print("=" * 40)
    print(f"Node ID: {stats['node_id']}")
    print(f"Role: {stats['role']}")
    print(f"Running: {stats['running']}")
    print(f"Capabilities: {', '.join(stats['capabilities'])}")
    print()

    print("Query Statistics:")
    for key, value in stats["stats"].items():
        formatted_key = key.replace("_", " ").title()
        print(f"  {formatted_key}: {value}")
    print()

    print("Current State:")
    print(f"  Active Queries: {stats['active_queries']}")
    print(f"  Pending Bundles: {stats['pending_bundles']}")
    print(f"  Known Nodes: {stats['known_nodes']}")
    print()

    print("Mixing Buffer:")
    for priority, count in stats["mixing_buffer_sizes"].items():
        if count > 0:
            print(f"  Priority {priority}: {count} queries")


def cmd_create_sample_queries(args):
    """Create a sample queries file."""
    sample_queries = [
        {
            "operation_type": "domain_lookup",
            "target": "example.com",
            "priority": 3,
            "anonymous": True,
        },
        {
            "operation_type": "whois_query",
            "target": "github.com",
            "priority": 2,
            "anonymous": True,
        },
        {
            "operation_type": "http_request",
            "target": "https://httpbin.org/ip",
            "parameters": {"method": "GET"},
            "priority": 3,
            "anonymous": True,
        },
        {
            "operation_type": "domain_lookup",
            "target": "google.com",
            "priority": 4,
            "anonymous": True,
        },
        {
            "operation_type": "whois_query",
            "target": "cloudflare.com",
            "priority": 3,
            "anonymous": True,
        },
    ]

    output_file = args.output or "sample_queries.json"

    try:
        with open(output_file, "w") as f:
            json.dump(sample_queries, f, indent=2)

        print(f"Created sample queries file: {output_file}")
        print(f"Contains {len(sample_queries)} sample queries")

    except Exception as e:
        print(f"Failed to create sample queries: {e}")
        return 1


def cmd_test_anonymity(args):
    """Test anonymity features with a series of queries."""
    print("Testing anonymity grid features...")
    print("=" * 50)

    # Initialize different node types
    consumer = AnonymityGrid(node_id="test_consumer", role=GridNodeRole.CONSUMER)
    mixer = AnonymityGrid(node_id="test_mixer", role=GridNodeRole.MIXER)

    consumer.start_grid_services()
    mixer.start_grid_services()

    # Add mixer to consumer's known nodes
    consumer.add_grid_node(
        "test_mixer", GridNodeRole.MIXER, {"query_mixing", "bundle_processing"}
    )

    print(f"✓ Started consumer node: {consumer.node_id}")
    print(f"✓ Started mixer node: {mixer.node_id}")
    print()

    # Submit test queries
    test_queries = [
        ("domain_lookup", "example.com"),
        ("whois_query", "test.org"),
        ("domain_lookup", "github.com"),
        ("http_request", "httpbin.org"),
    ]

    print(f"Submitting {len(test_queries)} test queries...")

    query_ids = []
    for operation, target in test_queries:
        query_id = consumer.submit_query(
            operation_type=operation,
            target=target,
            priority=QueryPriority.NORMAL,
            anonymous=True,
        )
        query_ids.append(query_id)
        print(f"  Submitted: {operation} on {target} (ID: {query_id[:8]}...)")

    # Wait for processing
    print("\nWaiting for query processing...")
    time.sleep(5)

    # Get results
    successful = 0
    for query_id in query_ids:
        result = consumer.get_query_result(query_id, timeout=10)
        if result:
            status = "✓" if result.success else "❌"
            print(f"  {status} {query_id[:8]}...: {status}")
            if result.success:
                successful += 1
        else:
            print(f"  ⏱ {query_id[:8]}...: Timeout")

    print(f"\nResults: {successful}/{len(query_ids)} queries successful")

    # Show statistics
    print("\nFinal Statistics:")
    consumer_stats = consumer.get_grid_statistics()
    mixer_stats = mixer.get_grid_statistics()

    print(
        f"Consumer - Submitted: {consumer_stats['stats']['queries_submitted']}, "
        f"Processed: {consumer_stats['stats']['queries_processed']}"
    )
    print(
        f"Mixer - Mixed: {mixer_stats['stats']['queries_mixed']}, "
        f"Bundles: {mixer_stats['stats']['bundles_created']}"
    )

    # Cleanup
    consumer.stop_grid_services()
    mixer.stop_grid_services()

    print("\n✓ Anonymity test completed")


def main():
    """Main CLI function."""
    parser = argparse.ArgumentParser(
        description="Anonymity Grid Management CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s start --role mixer --interactive      # Start mixer node
  %(prog)s query domain_lookup example.com       # Submit anonymous query
  %(prog)s batch queries.json                    # Process batch queries
  %(prog)s stats                                 # Show node statistics
  %(prog)s test                                  # Test anonymity features
  %(prog)s sample                                # Create sample queries
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Start node
    start_parser = subparsers.add_parser("start", help="Start anonymity grid node")
    start_parser.add_argument("--node-id", help="Node identifier")
    start_parser.add_argument(
        "--role",
        default="consumer",
        choices=[r.value for r in GridNodeRole],
        help="Node role",
    )
    start_parser.add_argument(
        "--interactive", action="store_true", help="Run in interactive mode"
    )
    start_parser.add_argument(
        "--show-stats", action="store_true", help="Show statistics in interactive mode"
    )
    start_parser.set_defaults(func=cmd_start_node)

    # Submit query
    query_parser = subparsers.add_parser("query", help="Submit anonymous query")
    query_parser.add_argument("operation", help="Operation type")
    query_parser.add_argument("target", help="Query target")
    query_parser.add_argument(
        "--priority",
        type=int,
        choices=[1, 2, 3, 4, 5],
        help="Query priority (1=urgent, 5=background)",
    )
    query_parser.add_argument("--parameters", help="JSON parameters")
    query_parser.add_argument(
        "--timeout", type=float, default=60.0, help="Query timeout in seconds"
    )
    query_parser.set_defaults(func=cmd_submit_query)

    # Batch queries
    batch_parser = subparsers.add_parser("batch", help="Process batch queries")
    batch_parser.add_argument("file", help="JSON file containing queries")
    batch_parser.add_argument(
        "--timeout", type=float, default=120.0, help="Timeout per query in seconds"
    )
    batch_parser.add_argument("--output", help="Output file for results")
    batch_parser.set_defaults(func=cmd_batch_query)

    # Node statistics
    stats_parser = subparsers.add_parser("stats", help="Show node statistics")
    stats_parser.set_defaults(func=cmd_node_stats)

    # Create sample queries
    sample_parser = subparsers.add_parser("sample", help="Create sample queries file")
    sample_parser.add_argument("--output", help="Output file path")
    sample_parser.set_defaults(func=cmd_create_sample_queries)

    # Test anonymity
    test_parser = subparsers.add_parser("test", help="Test anonymity features")
    test_parser.set_defaults(func=cmd_test_anonymity)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    try:
        return args.func(args) or 0
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
