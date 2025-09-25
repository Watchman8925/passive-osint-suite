#!/usr/bin/env python3

"""
Passive OSINT Suite - Combined Edition
Comprehensive passive reconnaissance and intelligence gathering tool
Specialized for transnational organized crime investigations
"""

import argparse
import os
import sys

from colorama import init
from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.table import Table

# Ensure project root is on path for local imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import the unified module system
from modules import MODULE_REGISTRY
# Import core utilities
from utils.osint_utils import OSINTUtils

# Force matplotlib to use a non-interactive backend so the suite is headless-safe
try:
    import matplotlib

    matplotlib.use("Agg")
except Exception:
    # If matplotlib isn't available yet or backend cannot be set, continue gracefully
    pass

# Initialize colorama and rich
init(autoreset=True)
console = Console()


class OSINTSuite:
    """Unified OSINT Suite using the modular architecture"""

    def __init__(self):
        """Initialize the OSINT Suite with all available modules"""
        self.utils = OSINTUtils()

        # Dynamically load all modules from the registry
        self.modules = {}
        for module_name, module_info in MODULE_REGISTRY.items():
            try:
                self.modules[module_name] = module_info["class"]()
                print(f"✅ Loaded module: {module_name}")
            except Exception as e:
                print(f"❌ Failed to load module {module_name}: {e}")

        # Keep backward compatibility by exposing modules as attributes
        self._setup_module_attributes()

    def _setup_module_attributes(self):
        """Set up module attributes for backward compatibility"""
        # Map common module names to their instances
        module_mapping = {
            "domain_recon": "domain_recon",
            "email_intel": "email_intel",
            "ip_intel": "ip_intel",
            "company_intel": "company_intel",
            "flight_intel": "flight_intel",
            "passive_search": "passive_search",
            "crypto_intel": "crypto_intel",
            "web_scraper": "web_scraper",
            "search_engine_dorking": "search_engine_dorking",
            "certificate_transparency": "certificate_transparency",
            "wayback_machine": "wayback_machine",
            "paste_site_monitor": "paste_site_monitor",
            "social_media_footprint": "social_media_footprint",
            "github_search": "github_search",
            "passive_dns_enum": "passive_dns_enum",
            "whois_history": "whois_history",
            "public_breach_search": "public_breach_search",
        }

        for attr_name, module_name in module_mapping.items():
            if module_name in self.modules:
                setattr(self, attr_name, self.modules[module_name])

    def get_module(self, module_name):
        """Get a module instance by name"""
        return self.modules.get(module_name)

    def list_available_modules(self):
        """List all available modules"""
        return list(self.modules.keys())

    def get_modules_by_category(self, category):
        """Get all modules in a specific category"""
        return [
            name
            for name, info in MODULE_REGISTRY.items()
            if info["category"] == category and name in self.modules
        ]

    def api_key_status_menu(self):
        """Display the status of all major API keys"""
        console.print("\n[bold cyan]🔑 API Key Status[/bold cyan]\n")
        from rich.table import Table

        key_map = [
            ("Shodan", "SHODAN_API_KEY", "High"),
            ("Alienvault", "ALIENVAULT_API_KEY", "Low"),
            ("Hunter", "HUNTER_API_KEY", "High"),
            ("Greynoise", "GREYNOISE_API_KEY", "Medium"),
            ("Securitytrails", "SECURITYTRAILS_API_KEY", "Low"),
            ("Googlesearch", "GOOGLESEARCH_API_KEY", "Low"),
            ("Virustotal", "VIRUSTOTAL_API_KEY", "High"),
            ("Abuseipdb", "ABUSEIPDB_API_KEY", "Medium"),
            ("Clearbit", "CLEARBIT_API_KEY", "Medium"),
            ("Whoisxml", "WHOISXML_API_KEY", "Low"),
            ("Intelx", "INTELX_API_KEY", "Low"),
            ("Etherscan", "ETHERSCAN_API_KEY", "Low"),
            ("Cryptocompare", "CRYPTOCOMPARE_API_KEY", "Low"),
            ("Flightaware", "FLIGHTAWARE_API_KEY", "Low"),
            ("Censys", "CENSYS_API_KEY", "Low"),
        ]
        api_keys = self.utils.get_all_api_keys()
        table = Table("Service", "Status", "Priority")
        configured = 0
        for name, key, priority in key_map:
            val = api_keys.get(key, "")
            if val and val.strip():
                table.add_row(name, "✅ Configured", priority)
                configured += 1
            else:
                table.add_row(name, "❌ Missing", priority)
        console.print(table)
        console.print(f"\nSummary: {configured}/{len(key_map)} API keys configured\n")

    def display_banner(self):
        """Display application banner"""
        self.utils.print_banner()

    def main_menu(self):
        """Display main menu and handle user input"""
        while True:
            console.print(
                "\n[bold cyan]═══ PASSIVE OSINT SUITE - ULTIMATE EDITION ═══[/bold cyan]\n"
            )

            menu_options = Table(show_header=False, show_edge=False, pad_edge=False)
            menu_options.add_column("Option", style="cyan", width=3)
            menu_options.add_column("Description", style="white")

            menu_options.add_row("1", "🌐 Domain Reconnaissance")
            menu_options.add_row("2", "📧 Email Intelligence")
            menu_options.add_row("3", "🔍 IP Address Analysis")
            menu_options.add_row("4", "🏢 Company Intelligence")
            menu_options.add_row("5", "✈️ Flight & Aviation Intelligence")
            menu_options.add_row("6", "🔎 Passive Search Intelligence")
            menu_options.add_row("7", "🧩 Passive Intelligence (Grouped)")
            menu_options.add_row("8", "₿ Cryptocurrency Intelligence")
            menu_options.add_row("9", "📊 Batch Analysis")
            menu_options.add_row("10", "📁 View Results")
            menu_options.add_row("11", "📑 Reporting & Analysis Suite")
            menu_options.add_row("12", "🧨 Run Everything (Full Suite Compilation)")
            menu_options.add_row("13", "⚙️ Configuration")
            menu_options.add_row("14", "🔧 System Status")
            menu_options.add_row("0", "❌ Exit")

            console.print(menu_options)

            choice = Prompt.ask(
                "\n[bold yellow]Select an option[/bold yellow]", default="0"
            )

            if choice == "1":
                self.domain_reconnaissance_menu()
            elif choice == "2":
                self.email_intelligence_menu()
            elif choice == "3":
                self.ip_analysis_menu()
            elif choice == "4":
                self.company_intelligence_menu()
            elif choice == "5":
                self.flight_intelligence_menu()
            elif choice == "6":
                self.passive_search_menu()
            elif choice == "7":
                self.passive_intelligence_menu()
            elif choice == "8":
                self.crypto_intelligence_menu()
            elif choice == "9":
                self.batch_analysis_menu()
            elif choice == "10":
                self.view_results_menu()
            elif choice == "11":
                self.reporting_analysis_suite_menu()
            elif choice == "12":
                self.run_everything_menu()
            elif choice == "13":
                self.configuration_menu()
            elif choice == "14":
                self.system_status_menu()
            elif choice == "0":
                console.print(
                    "\n[green]Thank you for using Passive OSINT Suite![/green]"
                )
                break
            else:
                console.print("\n[red]Invalid option. Please try again.[/red]")

    def domain_reconnaissance_menu(self):
        """Domain reconnaissance menu"""
        console.print("\n[bold blue]🌐 Domain Reconnaissance[/bold blue]")
        domain = Prompt.ask("Enter domain to analyze")
        if not domain:
            return

        console.print(f"\n[yellow]Analyzing domain: {domain}[/yellow]")

        with console.status("[bold green]Gathering intelligence..."):
            # Before running, check if any active checks will run and confirm with the user
            enable_active = self.utils.config.getboolean(
                "SETTINGS", "ENABLE_ACTIVE", fallback=False
            )
            if not enable_active:
                if Confirm.ask(
                    "Active checks (live network/TCP) are disabled. Temporarily enable for this domain analysis?",
                    default=False,
                ):
                    # Temporarily enable for this run
                    self.utils.config["SETTINGS"]["ENABLE_ACTIVE"] = "True"
                    # Re-instantiate DomainRecon to pick up updated config
                    self.domain_recon = self.get_module("domain_recon")
                    results = self.domain_recon.analyze_domain(domain)
                    # Revert the setting to False after run
                    self.utils.config["SETTINGS"]["ENABLE_ACTIVE"] = "False"
                    self.domain_recon = self.get_module("domain_recon")
                else:
                    # Run passive-only analysis
                    results = self.domain_recon.analyze_domain(domain)
            else:
                results = self.domain_recon.analyze_domain(domain)

        if results:
            # Display summary
            self.display_domain_summary(results)

            # Save results
            filename = self.utils.save_results(
                results, f"domain_recon_{domain.replace('.', '_')}"
            )
            console.print(f"\n[green]Results saved to: {filename}[/green]")

    def email_intelligence_menu(self):
        """Email intelligence menu"""
        console.print("\n[bold blue]📧 Email Intelligence[/bold blue]")
        email = Prompt.ask("Enter email address to analyze")
        if not email:
            return

        console.print(f"\n[yellow]Analyzing email: {email}[/yellow]")

        with console.status("[bold green]Gathering intelligence..."):
            results = self.email_intel.analyze_email(email)

        if results:
            # Display summary
            self.display_email_summary(results)

            # Save results
            filename = self.utils.save_results(
                results, f"email_intel_{email.replace('@', '_').replace('.', '_')}"
            )
            console.print(f"\n[green]Results saved to: {filename}[/green]")

    def ip_analysis_menu(self):
        """IP address analysis menu"""
        console.print("\n[bold blue]🔍 IP Address Analysis[/bold blue]")
        ip_address = Prompt.ask("Enter IP address to analyze")
        if not ip_address:
            return

        console.print(f"\n[yellow]Analyzing IP: {ip_address}[/yellow]")

        with console.status("[bold green]Gathering intelligence..."):
            enable_active = self.utils.config.getboolean(
                "SETTINGS", "ENABLE_ACTIVE", fallback=False
            )
            if not enable_active:
                if Confirm.ask(
                    "Active checks (live network/TCP) are disabled. Temporarily enable for this IP analysis?",
                    default=False,
                ):
                    self.utils.config["SETTINGS"]["ENABLE_ACTIVE"] = "True"
                    self.ip_intel = self.get_module("ip_intel")
                    results = self.ip_intel.analyze_ip(ip_address)
                    # Revert
                    self.utils.config["SETTINGS"]["ENABLE_ACTIVE"] = "False"
                    self.ip_intel = self.get_module("ip_intel")
                else:
                    results = self.ip_intel.analyze_ip(ip_address)
            else:
                results = self.ip_intel.analyze_ip(ip_address)

        if results:
            # Display summary
            self.display_ip_summary(results)

            # Save results
            filename = self.utils.save_results(
                results, f"ip_intel_{ip_address.replace('.', '_')}"
            )
            console.print(f"\n[green]Results saved to: {filename}[/green]")

    def company_intelligence_menu(self):
        """Company intelligence menu"""
        console.print("\n[bold blue]🏢 Company Intelligence[/bold blue]")
        company = Prompt.ask("Enter company name to analyze")
        if not company:
            return

        console.print(f"\n[yellow]Analyzing company: {company}[/yellow]")

        with console.status("[bold green]Gathering intelligence..."):
            results = self.company_intel.analyze_company(company)

        if results:
            # Display summary
            self.display_company_summary(results)

            # Save results
            filename = self.utils.save_results(
                results, f"company_intel_{company.replace(' ', '_')}"
            )
            console.print(f"\n[green]Results saved to: {filename}[/green]")

    def flight_intelligence_menu(self):
        """Flight intelligence menu"""
        console.print("\n[bold blue]✈️ Flight & Aviation Intelligence[/bold blue]")
        flight_number = Prompt.ask(
            "Enter flight number (e.g., AA123) or aircraft registration"
        )
        if not flight_number:
            return

        console.print(f"\n[yellow]Analyzing flight: {flight_number}[/yellow]")

        with console.status("[bold green]Gathering intelligence..."):
            results = self.flight_intel.analyze_flight(flight_number)

        if results:
            # Display summary
            self.display_flight_summary(results)

            # Save results
            filename = self.utils.save_results(
                results, f"flight_intel_{flight_number.replace(' ', '_')}"
            )
            console.print(f"\n[green]Results saved to: {filename}[/green]")

    def passive_search_menu(self):
        """Passive search intelligence menu"""
        console.print("\n[bold blue]🔎 Passive Search Intelligence[/bold blue]")
        target = Prompt.ask("Enter target to search for")
        if not target:
            return

        console.print(f"\n[yellow]Searching for: {target}[/yellow]")

        with console.status("[bold green]Searching across multiple sources..."):
            results = self.passive_search.analyze_target(target, "general")

        if results:
            # Display summary
            self.display_passive_search_summary(results)

            # Save results
            filename = self.utils.save_results(
                results, f"passive_search_{target.replace(' ', '_')}"
            )
            console.print(f"\n[green]Results saved to: {filename}[/green]")

    def passive_intelligence_menu(self):
        """Grouped passive intelligence menu"""
        console.print("\n[bold blue]🧩 Passive Intelligence (Grouped)[/bold blue]")
        console.print("This will run multiple passive intelligence modules...")

        # Get target
        target = Prompt.ask("Enter target (domain, email, IP, or company)")
        if not target:
            return

        console.print(
            f"\n[yellow]Running comprehensive passive intelligence on: {target}[/yellow]"
        )

        # Run multiple modules based on target type
        results = {}

        with console.status("[bold green]Running passive intelligence modules..."):
            # Domain analysis
            if "." in target and "@" not in target:
                domain_modules = self.get_modules_by_category("domain")
                for module_name in domain_modules:
                    module = self.get_module(module_name)
                    if hasattr(module, "analyze_domain"):
                        try:
                            results[module_name] = module.analyze_domain(target)
                        except Exception as e:
                            results[module_name] = {"error": str(e)}

            # Email analysis
            elif "@" in target:
                email_modules = self.get_modules_by_category("email")
                for module_name in email_modules:
                    module = self.get_module(module_name)
                    if hasattr(module, "analyze_email"):
                        try:
                            results[module_name] = module.analyze_email(target)
                        except Exception as e:
                            results[module_name] = {"error": str(e)}

            # IP analysis
            elif target.replace(".", "").isdigit():
                ip_modules = self.get_modules_by_category("network")
                for module_name in ip_modules:
                    module = self.get_module(module_name)
                    if hasattr(module, "analyze_ip"):
                        try:
                            results[module_name] = module.analyze_ip(target)
                        except Exception as e:
                            results[module_name] = {"error": str(e)}

        if results:
            # Display summary
            self.display_grouped_results(results)

            # Save results
            filename = self.utils.save_results(
                results,
                f"grouped_intel_{target.replace(' ', '_').replace('@', '_').replace('.', '_')}",
            )
            console.print(f"\n[green]Results saved to: {filename}[/green]")

    def crypto_intelligence_menu(self):
        """Cryptocurrency intelligence menu"""
        console.print("\n[bold blue]₿ Cryptocurrency Intelligence[/bold blue]")
        crypto_target = Prompt.ask(
            "Enter cryptocurrency address, transaction hash, or exchange"
        )
        if not crypto_target:
            return

        console.print(
            f"\n[yellow]Analyzing cryptocurrency target: {crypto_target}[/yellow]"
        )

        with console.status("[bold green]Gathering cryptocurrency intelligence..."):
            results = self.crypto_intel.analyze_crypto(crypto_target)

        if results:
            # Display summary
            self.display_crypto_summary(results)

            # Save results
            filename = self.utils.save_results(
                results, f"crypto_intel_{crypto_target[:10]}"
            )
            console.print(f"\n[green]Results saved to: {filename}[/green]")

    def batch_analysis_menu(self):
        """Batch analysis menu"""
        console.print("\n[bold blue]📊 Batch Analysis[/bold blue]")
        console.print("This feature allows you to analyze multiple targets at once.")

        # For now, show a placeholder
        console.print("[yellow]Batch analysis feature coming soon![/yellow]")

    def view_results_menu(self):
        """View results menu"""
        console.print("\n[bold blue]📁 View Results[/bold blue]")
        console.print("Recent analysis results:")

        # List recent result files
        results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
        if os.path.exists(results_dir):
            files = [f for f in os.listdir(results_dir) if f.endswith(".json")]
            if files:
                for i, file in enumerate(sorted(files, reverse=True)[:10]):
                    console.print(f"{i+1}. {file}")
            else:
                console.print("[yellow]No result files found.[/yellow]")
        else:
            console.print("[yellow]Results directory not found.[/yellow]")

    def reporting_analysis_suite_menu(self):
        """Reporting and analysis suite menu"""
        console.print("\n[bold blue]📑 Reporting & Analysis Suite[/bold blue]")
        console.print("Advanced reporting and analysis tools:")

        # For now, show a placeholder
        console.print("[yellow]Advanced reporting suite coming soon![/yellow]")

    def run_everything_menu(self):
        """Run everything menu"""
        console.print(
            "\n[bold blue]🧨 Run Everything (Full Suite Compilation)[/bold blue]"
        )
        console.print("[red]⚠️  WARNING: This will run ALL available modules![/red]")

        if not Confirm.ask(
            "Are you sure you want to run the full suite? This may take a while.",
            default=False,
        ):
            return

        target = Prompt.ask("Enter target for full analysis")
        if not target:
            return

        console.print(f"\n[yellow]Running full OSINT suite on: {target}[/yellow]")

        # Run all available modules
        all_results = {}

        with console.status("[bold green]Running complete OSINT analysis..."):
            for module_name, module in self.modules.items():
                try:
                    # Try different analysis methods based on target type
                    if (
                        hasattr(module, "analyze_domain")
                        and "." in target
                        and "@" not in target
                    ):
                        all_results[module_name] = module.analyze_domain(target)
                    elif hasattr(module, "analyze_email") and "@" in target:
                        all_results[module_name] = module.analyze_email(target)
                    elif (
                        hasattr(module, "analyze_ip")
                        and target.replace(".", "").isdigit()
                    ):
                        all_results[module_name] = module.analyze_ip(target)
                    elif hasattr(module, "analyze_company"):
                        all_results[module_name] = module.analyze_company(target)
                    elif hasattr(module, "scrape") and hasattr(module, "search"):
                        # Generic modules
                        if "web" in module_name:
                            all_results[module_name] = module.scrape(target)
                        elif "search" in module_name:
                            all_results[module_name] = module.search(target)
                except Exception as e:
                    all_results[module_name] = {"error": str(e)}

        if all_results:
            # Save comprehensive results
            filename = self.utils.save_results(
                all_results,
                f"full_suite_{target.replace(' ', '_').replace('@', '_').replace('.', '_')}",
            )
            console.print(f"\n[green]Complete analysis saved to: {filename}[/green]")

            # Show summary
            successful = sum(1 for r in all_results.values() if "error" not in r)
            console.print(
                f"\n[cyan]Analysis Summary: {successful}/{len(all_results)} modules completed successfully[/cyan]"
            )

    def configuration_menu(self):
        """Configuration menu"""
        console.print("\n[bold blue]⚙️ Configuration[/bold blue]")
        console.print("Configuration options:")

        # For now, show basic config info
        console.print(f"Config file: {self.utils._config_path}")
        console.print(f"Active modules: {len(self.modules)}")

    def system_status_menu(self):
        """System status menu"""
        console.print("\n[bold blue]🔧 System Status[/bold blue]")

        # Show module status
        table = Table("Component", "Status", "Details")
        table.add_row("Core Utils", "✅ Active", "OSINTUtils loaded")
        table.add_row(
            "Modules",
            f"✅ {len(self.modules)} loaded",
            f"Available: {', '.join(list(self.modules.keys())[:5])}...",
        )
        table.add_row("Configuration", "✅ Loaded", f"Path: {self.utils._config_path}")

        console.print(table)

        # Show API key status
        self.api_key_status_menu()

    # Summary display methods
    def display_domain_summary(self, results):
        """Display domain analysis summary"""
        console.print("\n[bold green]📊 Domain Analysis Summary[/bold green]")
        if "subdomains" in results:
            console.print(f"Subdomains found: {len(results['subdomains'])}")
        if "dns_records" in results:
            console.print(f"DNS records: {len(results['dns_records'])}")

    def display_email_summary(self, results):
        """Display email analysis summary"""
        console.print("\n[bold green]📊 Email Analysis Summary[/bold green]")
        if "breaches" in results:
            console.print(f"Breach records: {len(results['breaches'])}")
        if "social_profiles" in results:
            console.print(f"Social profiles: {len(results['social_profiles'])}")

    def display_ip_summary(self, results):
        """Display IP analysis summary"""
        console.print("\n[bold green]📊 IP Analysis Summary[/bold green]")
        if "geolocation" in results:
            geo = results["geolocation"]
            console.print(
                f"Location: {geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}"
            )
        if "reputation" in results:
            console.print(
                f"Reputation score: {results['reputation'].get('score', 'Unknown')}"
            )

    def display_company_summary(self, results):
        """Display company analysis summary"""
        console.print("\n[bold green]📊 Company Analysis Summary[/bold green]")
        if "domain" in results:
            console.print(f"Primary domain: {results['domain']}")
        if "social_media" in results:
            console.print(f"Social media profiles: {len(results['social_media'])}")

    def display_flight_summary(self, results):
        """Display flight analysis summary"""
        console.print("\n[bold green]📊 Flight Analysis Summary[/bold green]")
        if "flight_info" in results:
            flight = results["flight_info"]
            console.print(
                f"Flight: {flight.get('airline', 'Unknown')} {flight.get('flight_number', 'Unknown')}"
            )
            console.print(
                f"Route: {flight.get('origin', 'Unknown')} → {flight.get('destination', 'Unknown')}"
            )

    def display_passive_search_summary(self, results):
        """Display passive search summary"""
        console.print("\n[bold green]📊 Passive Search Summary[/bold green]")
        if "results" in results:
            console.print(f"Search results: {len(results['results'])}")

    def display_crypto_summary(self, results):
        """Display cryptocurrency analysis summary"""
        console.print("\n[bold green]📊 Cryptocurrency Analysis Summary[/bold green]")
        if "transactions" in results:
            console.print(f"Transactions found: {len(results['transactions'])}")
        if "balance" in results:
            console.print(f"Balance: {results['balance']}")

    def display_grouped_results(self, results):
        """Display grouped analysis results"""
        console.print("\n[bold green]📊 Grouped Intelligence Summary[/bold green]")

        successful = 0
        for module_name, result in results.items():
            if "error" not in result:
                successful += 1
                console.print(
                    f"✅ {module_name}: {len(result) if isinstance(result, dict) else 'Completed'}"
                )
            else:
                console.print(f"❌ {module_name}: {result['error']}")

        console.print(
            f"\nTotal: {successful}/{len(results)} modules completed successfully"
        )


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Passive OSINT Suite")
    parser.add_argument("--domain", help="Domain to analyze")
    parser.add_argument("--email", help="Email to analyze")
    parser.add_argument("--ip", help="IP address to analyze")
    parser.add_argument("--company", help="Company to analyze")
    parser.add_argument("--flight", help="Flight number to analyze")
    parser.add_argument("--crypto", help="Cryptocurrency target to analyze")
    parser.add_argument("--batch", help="Batch analysis file")
    parser.add_argument("--output", help="Output directory")

    args = parser.parse_args()

    # Initialize the suite
    suite = OSINTSuite()

    # Display banner
    suite.display_banner()

    # Handle command line arguments
    if args.domain:
        suite.domain_recon = suite.get_module("domain_recon")
        results = suite.domain_recon.analyze_domain(args.domain)
        if results:
            filename = suite.utils.save_results(
                results, f"domain_recon_{args.domain.replace('.', '_')}"
            )
            console.print(f"[green]Results saved to: {filename}[/green]")
        return

    elif args.email:
        suite.email_intel = suite.get_module("email_intel")
        results = suite.email_intel.analyze_email(args.email)
        if results:
            filename = suite.utils.save_results(
                results, f"email_intel_{args.email.replace('@', '_').replace('.', '_')}"
            )
            console.print(f"[green]Results saved to: {filename}[/green]")
        return

    elif args.ip:
        suite.ip_intel = suite.get_module("ip_intel")
        results = suite.ip_intel.analyze_ip(args.ip)
        if results:
            filename = suite.utils.save_results(
                results, f"ip_intel_{args.ip.replace('.', '_')}"
            )
            console.print(f"[green]Results saved to: {filename}[/green]")
        return

    elif args.company:
        suite.company_intel = suite.get_module("company_intel")
        results = suite.company_intel.analyze_company(args.company)
        if results:
            filename = suite.utils.save_results(
                results, f"company_intel_{args.company.replace(' ', '_')}"
            )
            console.print(f"[green]Results saved to: {filename}[/green]")
        return

    elif args.flight:
        suite.flight_intel = suite.get_module("flight_intel")
        results = suite.flight_intel.analyze_flight(args.flight)
        if results:
            filename = suite.utils.save_results(
                results, f"flight_intel_{args.flight.replace(' ', '_')}"
            )
            console.print(f"[green]Results saved to: {filename}[/green]")
        return

    elif args.crypto:
        suite.crypto_intel = suite.get_module("crypto_intel")
        results = suite.crypto_intel.analyze_crypto(args.crypto)
        if results:
            filename = suite.utils.save_results(
                results, f"crypto_intel_{args.crypto[:10]}"
            )
            console.print(f"[green]Results saved to: {filename}[/green]")
        return

    # If no arguments, show interactive menu
    suite.main_menu()


if __name__ == "__main__":
    main()
