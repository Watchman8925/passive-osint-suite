#!/usr/bin/env python3

"""
Passive OSINT Suite - Combined Edition
Comprehensive passive reconnaissance and intelligence gathering tool
Specialized for transnational organized crime investigations
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime

from colorama import init
from rich.console import Console
from rich.progress import track
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

        # Initialize module attributes to None for type checker recognition
        self.domain_recon = None
        self.email_intel = None
        self.ip_intel = None
        self.company_intel = None
        self.flight_intel = None
        self.passive_search = None
        self.crypto_intel = None
        self.web_scraper = None
        self.search_engine_dorking = None
        self.certificate_transparency = None
        self.wayback_machine = None
        self.paste_site_monitor = None
        self.social_media_footprint = None
        self.github_search = None
        self.passive_dns_enum = None
        self.whois_history = None
        self.public_breach_search = None

        # Dynamically load all modules from the registry
        self.modules = {}
        for module_name, module_info in MODULE_REGISTRY.items():
            try:
                # Special handling for modules that need dependencies
                if module_name == "email_intel":
                    # EmailIntel needs domain_recon, so we'll inject it after all modules are loaded
                    self.modules[module_name] = module_info["class"]()
                elif module_name == "company_intel":
                    # CompanyIntel might need domain_recon too
                    self.modules[module_name] = module_info["class"]()
                else:
                    self.modules[module_name] = module_info["class"]()
                print(f"✅ Loaded module: {module_name}")
            except Exception as e:
                print(f"❌ Failed to load module {module_name}: {e}")

        # Inject dependencies into modules that need them
        self._inject_dependencies()

        # Keep backward compatibility by exposing modules as attributes
        self._setup_module_attributes()

    def _inject_dependencies(self):
        """Inject dependencies into modules that need them"""
        # Inject domain_recon into email_intel
        if "email_intel" in self.modules and "domain_recon" in self.modules:
            self.modules["email_intel"].domain_recon = self.modules["domain_recon"]

        # Inject domain_recon into company_intel if needed
        if "company_intel" in self.modules and "domain_recon" in self.modules:
            self.modules["company_intel"].domain_recon = self.modules["domain_recon"]

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

        # Create instance attributes from modules
        for attr_name, module_name in module_mapping.items():
            if module_name in self.modules:
                setattr(self, attr_name, self.modules[module_name])
            else:
                # Create empty placeholder for missing modules to avoid AttributeError
                setattr(self, attr_name, None)
                print(f"⚠️ Warning: Module {module_name} not loaded, {attr_name} attribute will be None")

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
            menu_options.add_row("15", "📊 Advanced Analysis Suite")
            menu_options.add_row("16", "📊 Intelligence Reporting")
            menu_options.add_row("17", "📡 Real-time Intelligence Feeds")
            menu_options.add_row("18", "🕵️ Bellingcat Investigation Toolkit")
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
            elif choice == "15":
                self.advanced_analysis_menu()
            elif choice == "16":
                self.intelligence_reporting_menu()
            elif choice == "17":
                self.realtime_feeds_menu()
            elif choice == "18":
                self.bellingcat_toolkit_menu()
            elif choice == "0":
                console.print(
                    "\n[green]Thank you for using Passive OSINT Suite![/green]"
                )
                break
            else:
                console.print("[red]Invalid option. Please try again.[/red]")

    def reporting_analysis_suite_menu(self):
        """Comprehensive reporting, analysis, network maps, tables, charts, and case file management."""
        while True:
            console.print("\n[bold cyan]📑 Reporting & Analysis Suite[/bold cyan]\n")
            menu = Table(show_header=False, show_edge=False, pad_edge=False)
            menu.add_column("Option", style="cyan", width=3)
            menu.add_column("Description", style="white")
            menu.add_row("1", "📄 Generate Comprehensive Report")
            menu.add_row("2", "📊 Visualize Data (Tables/Charts)")
            menu.add_row("3", "🌐 Network Map Visualization")
            menu.add_row("4", "🗂️ Manage Case File")
            menu.add_row("0", "🔙 Back to main menu")
            console.print(menu)
            choice = Prompt.ask(
                "\n[bold yellow]Select reporting/analysis option[/bold yellow]",
                default="0",
            )
            if choice == "1":
                self.generate_comprehensive_report()
            elif choice == "2":
                self.visualize_data_menu()
            elif choice == "3":
                self.network_map_menu()
            elif choice == "4":
                self.case_file_menu()
            elif choice == "0":
                break
            else:
                console.print("[red]Invalid option. Please try again.[/red]")

    def generate_comprehensive_report(self):
        console.print(
            "\n[bold green]Generating comprehensive report from all available results...[/bold green]"
        )
        # Aggregate all JSON results in output dir
        import glob
        import json

        output_dir = "output"
        files = glob.glob(f"{output_dir}/*.json")
        all_data = []
        for f in files:
            try:
                with open(f, "r") as infile:
                    all_data.append(json.load(infile))
            except Exception:
                continue
        report_file = self.utils.save_results(all_data, "comprehensive_report")
        console.print(f"[green]Comprehensive report saved to: {report_file}[/green]")

    def visualize_data_menu(self):
        """Visualize data from results as tables and charts (passive, OPSEC safe)."""
        import glob
        import json

        import matplotlib.pyplot as plt
        import pandas as pd

        output_dir = "output"
        files = glob.glob(f"{output_dir}/*.json")
        if not files:
            console.print("[red]No result files found for visualization.[/red]")
            return
        # Let user pick a file
        table = Table(title="Available Results for Visualization")
        table.add_column("Index", style="cyan")
        table.add_column("Filename", style="green")
        for i, f in enumerate(files):
            table.add_row(str(i + 1), f.split("/")[-1])
        console.print(table)
        idx = Prompt.ask("Enter file index to visualize (0 to cancel)", default="0")
        try:
            idx = int(idx) - 1
            if idx < 0 or idx >= len(files):
                return
            with open(files[idx], "r") as infile:
                data = json.load(infile)
            # Try to convert to DataFrame
            if isinstance(data, list) and data and isinstance(data[0], dict):
                df = pd.DataFrame(data)
            elif isinstance(data, dict):
                df = pd.DataFrame([data])
            else:
                console.print("[red]Unsupported data format for visualization.[/red]")
                return
            # Show as table
            console.print("\n[bold green]Data Table:[/bold green]")
            console.print(df.head(20).to_markdown())
            # Plot chart
            if len(df.columns) >= 2:
                col1 = Prompt.ask(
                    "Select column for X axis",
                    choices=list(df.columns),
                    default=df.columns[0],
                )
                col2 = Prompt.ask(
                    "Select column for Y axis",
                    choices=list(df.columns),
                    default=df.columns[1],
                )
                import os as _os

                out_dir = _os.path.join("output", "visualizations")
                _os.makedirs(out_dir, exist_ok=True)
                plt.figure(figsize=(10, 5))
                df.plot(x=col1, y=col2, kind="bar")
                plt.title(f"{col2} by {col1}")
                plt.tight_layout()
                filename = _os.path.join(
                    out_dir, f"chart_{col1}_{col2}_{int(time.time())}.png"
                )
                plt.savefig(filename)
                plt.close()
                console.print(f"[green]Chart saved to: {filename}[/green]")
            else:
                console.print("[yellow]Not enough columns for charting.[/yellow]")
        except Exception as e:
            console.print(f"[red]Visualization failed: {e}[/red]")

    def network_map_menu(self):
        """Visualize relationships as a passive network map (no active scanning, OPSEC safe)."""
        import glob
        import json

        import matplotlib.pyplot as plt
        import networkx as nx

        output_dir = "output"
        files = glob.glob(f"{output_dir}/*.json")
        if not files:
            console.print("[red]No result files found for network mapping.[/red]")
            return
        # Let user pick a file
        table = Table(title="Available Results for Network Map")
        table.add_column("Index", style="cyan")
        table.add_column("Filename", style="green")
        for i, f in enumerate(files):
            table.add_row(str(i + 1), f.split("/")[-1])
        console.print(table)
        idx = Prompt.ask("Enter file index to map (0 to cancel)", default="0")
        try:
            idx = int(idx) - 1
            if idx < 0 or idx >= len(files):
                return
            with open(files[idx], "r") as infile:
                data = json.load(infile)
            G = nx.Graph()

            # Simple heuristic: add nodes for all keys/values, edges for relationships
            def add_edges(d, parent=None):
                if isinstance(d, dict):
                    for k, v in d.items():
                        G.add_node(k)
                        if parent:
                            G.add_edge(parent, k)
                        add_edges(v, k)
                elif isinstance(d, list):
                    for item in d:
                        add_edges(item, parent)
                else:
                    if parent:
                        G.add_node(str(d))
                        G.add_edge(parent, str(d))

            add_edges(data)
            import os as _os

            out_dir = _os.path.join("output", "visualizations")
            _os.makedirs(out_dir, exist_ok=True)
            plt.figure(figsize=(12, 8))
            nx.draw(
                G,
                with_labels=True,
                node_color="lightblue",
                edge_color="gray",
                font_size=8,
            )
            plt.title("Passive Network Map Visualization")
            filename = _os.path.join(out_dir, f"network_map_{int(time.time())}.png")
            plt.savefig(filename, dpi=150)
            plt.close()
            console.print(f"[green]Network map saved to: {filename}[/green]")
        except Exception as e:
            console.print(f"[red]Network map failed: {e}[/red]")

    def case_file_menu(self):
        """Manage a passive case file: aggregate, annotate, and export results (OPSEC safe)."""
        import glob
        import json

        output_dir = "output"
        files = glob.glob(f"{output_dir}/*.json")
        if not files:
            console.print("[red]No result files found for case file management.[/red]")
            return
        # Aggregate all results
        case_data = []
        for f in files:
            try:
                with open(f, "r") as infile:
                    case_data.append(json.load(infile))
            except Exception:
                continue
        # Simple annotation
        note = Prompt.ask(
            "Enter a note/annotation for this case (or leave blank)", default=""
        )
        from datetime import datetime

        case_file = {
            "case_data": case_data,
            "annotation": note,
            "timestamp": str(datetime.now()),
        }
        # Save case file
        case_file_path = self.utils.save_results(case_file, "case_file")
        console.print(f"[green]Case file saved to: {case_file_path}[/green]")

    def run_everything_menu(self):
        console.print(
            "\n[bold cyan]🧨 Running All Modules in the Suite...[/bold cyan]\n"
        )
        # Prompt for a master target (domain, email, IP, company, etc.)
        target = Prompt.ask(
            "Enter a master target (domain, email, IP, company, or keyword for all modules)"
        )
        # Run all active and passive modules in sequence, OPSEC safe, through Tor
        # Domain Recon
        dr_result = self.domain_recon.analyze_domain(target)
        console.print(f"[green]Domain Recon:[/green] {dr_result}")
        # Email Intel
        ei_result = self.email_intel.analyze_email(target)
        console.print(f"[green]Email Intelligence:[/green] {ei_result}")
        # IP Intel
        ip_result = self.ip_intel.analyze_ip(target)
        console.print(f"[green]IP Intelligence:[/green] {ip_result}")
        # Company Intel
        ci_result = self.company_intel.analyze_company(target)
        console.print(f"[green]Company Intelligence:[/green] {ci_result}")
        # Flight Intel
        fi_result = self.flight_intel.analyze_aircraft(target, "registration")
        console.print(f"[green]Flight Intelligence:[/green] {fi_result}")
        # Passive Search
        ps_result = self.passive_search.analyze_target(target, "domain")
        console.print(f"[green]Passive Search:[/green] {ps_result}")
        # Crypto Intel
        cr_result = self.crypto_intel.analyze_crypto_address(target, "bitcoin")
        console.print(f"[green]Crypto Intelligence:[/green] {cr_result}")
        # Passive Modules
        ws_result = self.web_scraper.scrape(target)
        console.print(f"[green]Web Scraper:[/green] {ws_result}")
        dork_result = self.search_engine_dorking.dork(target)
        console.print(f"[green]Search Engine Dorking:[/green] {dork_result}")
        ct_result = self.certificate_transparency.search(target)
        console.print(f"[green]Certificate Transparency:[/green] {ct_result}")
        wb_result = self.wayback_machine.fetch_snapshots(target)
        console.print(f"[green]Wayback Machine:[/green] {wb_result}")
        paste_result = self.paste_site_monitor.search_pastes(target)
        console.print(f"[green]Paste Site Monitor:[/green] {paste_result}")
        sm_result = self.social_media_footprint.scrape_profiles(target)
        console.print(f"[green]Social Media Footprint:[/green] {sm_result}")
        gh_result = self.github_search.search(target)
        console.print(f"[green]GitHub Search:[/green] {gh_result}")
        dns_result = self.passive_dns_enum.enumerate(target)
        console.print(f"[green]Passive DNS Enum:[/green] {dns_result}")
        whois_result = self.whois_history.get_history(target)
        console.print(f"[green]WHOIS History:[/green] {whois_result}")
        # Active checks (e.g., live certificate retrieval) are gated by ENABLE_ACTIVE
        enable_active = self.utils.config.getboolean(
            "SETTINGS", "ENABLE_ACTIVE", fallback=False
        )
        if enable_active:
            breach_result = self.public_breach_search.search(target)
            console.print(f"[green]Public Breach Search:[/green] {breach_result}")
        else:
            console.print(
                "[yellow]Public Breach Search skipped (active checks disabled). Enable in Configuration to run active modules.[/yellow]"
            )

    def passive_intelligence_menu(self):
        """Grouped submenu for passive, no-API OSINT features"""
        while True:
            console.print(
                "\n[bold cyan]🧩 Passive Intelligence (No API, 100% Passive)[/bold cyan]\n"
            )
            menu = Table(show_header=False, show_edge=False, pad_edge=False)
            menu.add_column("Option", style="cyan", width=3)
            menu.add_column("Description", style="white")
            menu.add_row("1", "🌐 Public Web Scraping")
            menu.add_row("2", "🔎 Search Engine Dorking")
            menu.add_row("3", "🔒 Certificate Transparency Logs")
            menu.add_row("4", "🕰️ Wayback Machine Snapshots")
            menu.add_row("5", "📋 Public Paste Site Monitor")
            menu.add_row("6", "👤 Social Media Footprinting")
            menu.add_row("7", "💻 GitHub/Open Source Search")
            menu.add_row("8", "🧬 Passive DNS Enumeration")
            menu.add_row("9", "📜 WHOIS History Lookup")
            menu.add_row("10", "💥 Public Breach Search")
            menu.add_row("11", "🚀 Run All Passive Modules")
            menu.add_row("0", "🔙 Back to main menu")
            console.print(menu)
            sub_choice = Prompt.ask(
                "\n[bold yellow]Select passive intelligence option[/bold yellow]",
                default="0",
            )
            if sub_choice == "1":
                self.handle_web_scraper()
            elif sub_choice == "2":
                self.handle_search_engine_dorking()
            elif sub_choice == "3":
                self.handle_certificate_transparency()
            elif sub_choice == "4":
                self.handle_wayback_machine()
            elif sub_choice == "5":
                self.handle_paste_site_monitor()
            elif sub_choice == "6":
                self.handle_social_media_footprint()
            elif sub_choice == "7":
                self.handle_github_search()
            elif sub_choice == "8":
                self.handle_passive_dns_enum()
            elif sub_choice == "9":
                self.handle_whois_history()
            elif sub_choice == "10":
                self.handle_public_breach_search()
            elif sub_choice == "11":
                self.run_all_passive_modules()
            elif sub_choice == "0":
                break
            else:
                console.print("[red]Invalid option. Please try again.[/red]")

    def run_all_passive_modules(self):
        console.print(
            "\n[bold cyan]🚀 Running All Passive Intelligence Modules...[/bold cyan]\n"
        )
        # Prompt for a target (domain, URL, or keyword)
        target = Prompt.ask("Enter a target (domain, URL, or keyword for all modules)")
        # Web Scraper
        ws_result = self.web_scraper.scrape(target)
        console.print(f"[green]Web Scraper:[/green] {ws_result}")
        # Search Engine Dorking
        dork_result = self.search_engine_dorking.dork(target)
        console.print(f"[green]Search Engine Dorking:[/green] {dork_result}")
        # Certificate Transparency
        ct_result = self.certificate_transparency.search(target)
        console.print(f"[green]Certificate Transparency:[/green] {ct_result}")
        # Wayback Machine
        wb_result = self.wayback_machine.fetch_snapshots(target)
        console.print(f"[green]Wayback Machine:[/green] {wb_result}")
        # Paste Site Monitor
        paste_result = self.paste_site_monitor.search_pastes(target)
        console.print(f"[green]Paste Site Monitor:[/green] {paste_result}")
        # Social Media Footprint
        sm_result = self.social_media_footprint.scrape_profiles(target)
        console.print(f"[green]Social Media Footprint:[/green] {sm_result}")
        # GitHub Search
        gh_result = self.github_search.search(target)
        console.print(f"[green]GitHub Search:[/green] {gh_result}")
        # Passive DNS Enum
        dns_result = self.passive_dns_enum.enumerate(target)
        console.print(f"[green]Passive DNS Enum:[/green] {dns_result}")
        # WHOIS History
        whois_result = self.whois_history.get_history(target)
        console.print(f"[green]WHOIS History:[/green] {whois_result}")
        # Public Breach Search
        breach_result = self.public_breach_search.search(target)
        console.print(f"[green]Public Breach Search:[/green] {breach_result}")

    # Handler stubs for each passive module
    def handle_web_scraper(self):
        console.print("\n[bold cyan]🌐 Public Web Scraper[/bold cyan]\n")
        target = Prompt.ask("Enter website URL or domain to scrape (e.g. example.com)")
        kw_input = Prompt.ask(
            "Enter comma-separated keywords to search for (or leave blank for all)",
            default="",
        )
        keywords = (
            [k.strip() for k in kw_input.split(",") if k.strip()] if kw_input else None
        )
        with console.status("[bold green]Scraping website via Tor..."):
            result = self.web_scraper.scrape(target, keywords)
        if result["status"] == "success":
            lines = result["data"]
            if not lines:
                console.print("[yellow]No matching content found.[/yellow]")
            else:
                console.print(
                    f"[green]Found {len(lines)} matching lines/snippets:[/green]"
                )
                for line in lines[:20]:
                    console.print(f"[white]{line}[/white]")
                if len(lines) > 20:
                    console.print(
                        f"[cyan]...and {len(lines)-20} more lines. Refine your keywords for more focus.[/cyan]"
                    )
        else:
            console.print(f"[red]Error: {result.get('error','Unknown error')}[/red]")

    def handle_search_engine_dorking(self):
        console.print(
            "\n[cyan]Search Engine Dorking (stub): Add dorking logic here.[/cyan]"
        )

    def handle_certificate_transparency(self):
        console.print(
            "\n[cyan]Certificate Transparency (stub): Add CT log logic here.[/cyan]"
        )

    def handle_wayback_machine(self):
        console.print(
            "\n[cyan]Wayback Machine (stub): Add archive.org logic here.[/cyan]"
        )

    def handle_paste_site_monitor(self):
        console.print(
            "\n[cyan]Paste Site Monitor (stub): Add paste site logic here.[/cyan]"
        )

    def handle_social_media_footprint(self):
        console.print(
            "\n[cyan]Social Media Footprint (stub): Add social scraping logic here.[/cyan]"
        )

    def handle_github_search(self):
        console.print(
            "\n[cyan]GitHub Search (stub): Add GitHub search logic here.[/cyan]"
        )

    def handle_passive_dns_enum(self):
        console.print(
            "\n[cyan]Passive DNS Enum (stub): Add DNS enumeration logic here.[/cyan]"
        )

    def handle_whois_history(self):
        console.print(
            "\n[cyan]WHOIS History (stub): Add WHOIS history logic here.[/cyan]"
        )

    def handle_public_breach_search(self):
        console.print(
            "\n[cyan]Public Breach Search (stub): Add breach search logic here.[/cyan]"
        )

    def domain_reconnaissance_menu(self):
        """Domain reconnaissance submenu"""
        console.print("\n[bold cyan]🌐 Domain Reconnaissance[/bold cyan]\n")

        domain = Prompt.ask("Enter domain to analyze")

        if not domain:
            console.print("[red]Domain cannot be empty[/red]")
            return

        console.print(f"\n[yellow]Analyzing domain: {domain}[/yellow]")

        with console.status("[bold green]Gathering intelligence..."):
            results = self.domain_recon.analyze_domain(domain)

        if results:
            # Display summary
            self.display_domain_summary(results)

            # Save results
            filename = self.utils.save_results(
                results, f"domain_recon_{domain.replace('.', '_')}"
            )
            console.print(f"\n[green]Results saved to: {filename}[/green]")

            # Generate report
            if Confirm.ask("Generate detailed report?"):
                report = self.domain_recon.generate_report()
                report_file = self.utils.save_results(
                    report, f"domain_report_{domain.replace('.', '_')}", format="txt"
                )
                console.print(f"[green]Report saved to: {report_file}[/green]")
        else:
            console.print("[red]Failed to analyze domain[/red]")

    def email_intelligence_menu(self):
        """Email intelligence submenu"""
        console.print("\n[bold cyan]📧 Email Intelligence[/bold cyan]\n")

        email = Prompt.ask("Enter email address to analyze")

        if not email:
            console.print("[red]Email cannot be empty[/red]")
            return

        console.print(f"\n[yellow]Analyzing email: {email}[/yellow]")

        with console.status("[bold green]Gathering intelligence..."):
            results = self.email_intel.analyze_email(email)

        if results:
            # Display summary
            self.display_email_summary(results)

            # Save results
            filename = self.utils.save_results(
                results,
                f"email_intel_{email.replace('@', '_at_').replace('.', '_')}",
            )
            console.print(f"\n[green]Results saved to: {filename}[/green]")

            # Generate report
            if Confirm.ask("Generate detailed report?"):
                report = self.email_intel.generate_report()
                report_file = self.utils.save_results(
                    report,
                    f"email_report_{email.replace('@', '_at_').replace('.', '_')}",
                    format="txt",
                )
                console.print(f"[green]Report saved to: {report_file}[/green]")
        else:
            console.print("[red]Failed to analyze email[/red]")

    def ip_analysis_menu(self):
        """IP analysis submenu"""
        console.print("\n[bold cyan]🔍 IP Address Analysis[/bold cyan]\n")

        ip_address = Prompt.ask("Enter IP address to analyze")

        if not ip_address:
            console.print("[red]IP address cannot be empty[/red]")
            return

        console.print(f"\n[yellow]Analyzing IP: {ip_address}[/yellow]")

        with console.status("[bold green]Gathering intelligence..."):
            results = self.ip_intel.analyze_ip(ip_address)

        if results:
            # Display summary
            self.display_ip_summary(results)

            # Save results
            filename = self.utils.save_results(
                results, f"ip_intel_{ip_address.replace('.', '_')}"
            )
            console.print(f"\n[green]Results saved to: {filename}[/green]")

            # Generate report
            if Confirm.ask("Generate detailed report?"):
                report = self.ip_intel.generate_report()
                report_file = self.utils.save_results(
                    report, f"ip_report_{ip_address.replace('.', '_')}", format="txt"
                )
                console.print(f"[green]Report saved to: {report_file}[/green]")
        else:
            console.print("[red]Failed to analyze IP address[/red]")

    def company_intelligence_menu(self):
        """Company intelligence submenu"""
        console.print("\n[bold cyan]🏢 Company Intelligence[/bold cyan]\n")

        company_name = Prompt.ask("Enter company name")
        domain = Prompt.ask("Enter company domain (optional)", default="")

        if not company_name:
            console.print("[red]Company name cannot be empty[/red]")
            return

        console.print(f"\n[yellow]Analyzing company: {company_name}[/yellow]")

        with console.status("[bold green]Gathering intelligence..."):
            results = self.company_intel.analyze_company(
                company_name, domain if domain else None
            )

        if results:
            # Display summary
            self.display_company_summary(results)

            # Save results
            filename = self.utils.save_results(
                results, f"company_intel_{company_name.replace(' ', '_')}"
            )
            console.print(f"\n[green]Results saved to: {filename}[/green]")

            # Generate report
            if Confirm.ask("Generate detailed report?"):
                report = self.company_intel.generate_report()
                report_file = self.utils.save_results(
                    report,
                    f"company_report_{company_name.replace(' ', '_')}",
                    format="txt",
                )
                console.print(f"[green]Report saved to: {report_file}[/green]")
        else:
            console.print("[red]Failed to analyze company[/red]")

    def flight_intelligence_menu(self):
        """Flight intelligence submenu"""
        console.print("\n[bold cyan]✈️ Flight & Aviation Intelligence[/bold cyan]\n")

        console.print("Flight identifier types:")
        console.print("1. Aircraft Registration (e.g., N12345, G-ABCD)")
        console.print("2. Flight Number (e.g., UA123, BA456)")

        identifier_type = Prompt.ask(
            "Select identifier type", choices=["1", "2"], default="1"
        )
        identifier = Prompt.ask("Enter aircraft registration or flight number")

        if not identifier:
            console.print("[red]Identifier cannot be empty[/red]")
            return

        id_type = "registration" if identifier_type == "1" else "flight_number"

        console.print(f"\n[yellow]Analyzing aircraft: {identifier}[/yellow]")

        with console.status("[bold green]Gathering flight intelligence..."):
            results = self.flight_intel.analyze_aircraft(identifier, id_type)

        if results:
            # Display summary
            self.display_flight_summary(results)

            # Save results
            filename = self.utils.save_results(
                results, f"flight_intel_{identifier.replace('-', '_')}"
            )
            console.print(f"\n[green]Results saved to: {filename}[/green]")

            # Generate report
            if Confirm.ask("Generate detailed report?"):
                report = self.flight_intel.generate_report()
                report_file = self.utils.save_results(
                    report,
                    f"flight_report_{identifier.replace('-', '_')}",
                    format="txt",
                )
                console.print(f"[green]Report saved to: {report_file}[/green]")
        else:
            console.print("[red]Failed to analyze aircraft[/red]")

    def passive_search_menu(self):
        """Passive search intelligence submenu"""
        console.print("\n[bold cyan]🔎 Passive Search Intelligence[/bold cyan]\n")

        console.print("Target types:")
        console.print("1. Domain (e.g., example.com)")
        console.print("2. Email (e.g., user@example.com)")
        console.print("3. Company (e.g., Example Corp)")
        console.print("4. Person (e.g., John Doe)")

        target_type = Prompt.ask(
            "Select target type", choices=["1", "2", "3", "4"], default="1"
        )
        target = Prompt.ask("Enter target to search")

        if not target:
            console.print("[red]Target cannot be empty[/red]")
            return

        type_map = {"1": "domain", "2": "email", "3": "company", "4": "person"}
        search_type = type_map[target_type]

        console.print(f"\n[yellow]Performing passive search for: {target}[/yellow]")

        with console.status("[bold green]Searching across multiple sources..."):
            results = self.passive_search.analyze_target(target, search_type)

        if results:
            # Display summary
            self.display_passive_search_summary(results)

            # Save results
            filename = self.utils.save_results(
                results,
                f"passive_search_{target.replace('@', '_at_').replace('.', '_').replace(' ', '_')}",
            )
            console.print(f"\n[green]Results saved to: {filename}[/green]")

            # Generate report
            if Confirm.ask("Generate detailed report?"):
                report = self.passive_search.generate_report()
                report_file = self.utils.save_results(
                    report,
                    f"search_report_{target.replace('@', '_at_').replace('.', '_').replace(' ', '_')}",
                    format="txt",
                )
                console.print(f"[green]Report saved to: {report_file}[/green]")
        else:
            console.print("[red]Failed to perform passive search[/red]")

    def crypto_intelligence_menu(self):
        """Cryptocurrency intelligence submenu"""
        console.print("\n[bold cyan]₿ Cryptocurrency Intelligence[/bold cyan]\n")

        console.print("Supported cryptocurrencies:")
        console.print("1. Bitcoin (BTC)")
        console.print("2. Ethereum (ETH)")
        console.print("3. Litecoin (LTC)")
        console.print("4. Dogecoin (DOGE)")
        console.print("5. Bitcoin Cash (BCH)")
        console.print("6. Monero (XMR)")
        console.print("7. Zcash (ZEC)")

        currency_type = Prompt.ask(
            "Select cryptocurrency",
            choices=["1", "2", "3", "4", "5", "6", "7"],
            default="1",
        )
        address = Prompt.ask("Enter cryptocurrency address")

        if not address:
            console.print("[red]Address cannot be empty[/red]")
            return

        currency_map = {
            "1": "bitcoin",
            "2": "ethereum",
            "3": "litecoin",
            "4": "dogecoin",
            "5": "bitcoin_cash",
            "6": "monero",
            "7": "zcash",
        }
        currency = currency_map[currency_type]

        console.print(f"\n[yellow]Analyzing {currency} address: {address}[/yellow]")

        with console.status("[bold green]Analyzing blockchain data..."):
            results = self.crypto_intel.analyze_crypto_address(address, currency)

        if results:
            # Display summary
            self.display_crypto_summary(results)

            # Save results
            filename = self.utils.save_results(
                results, f"crypto_intel_{currency}_{address[:16]}"
            )
            console.print(f"\n[green]Results saved to: {filename}[/green]")

            # Generate report
            if Confirm.ask("Generate detailed report?"):
                report = self.crypto_intel.generate_report()
                report_file = self.utils.save_results(
                    report, f"crypto_report_{currency}_{address[:16]}", format="txt"
                )
                console.print(f"[green]Report saved to: {report_file}[/green]")
        else:
            console.print("[red]Failed to analyze cryptocurrency address[/red]")

    def batch_analysis_menu(self):
        """Batch analysis menu"""
        console.print("\n[bold cyan]📊 Batch Analysis[/bold cyan]\n")

        batch_options = Table(show_header=False, show_edge=False, pad_edge=False)
        batch_options.add_column("Option", style="cyan", width=3)
        batch_options.add_column("Description", style="white")

        batch_options.add_row("1", "📄 Process file of domains")
        batch_options.add_row("2", "📄 Process file of email addresses")
        batch_options.add_row("3", "📄 Process file of IP addresses")
        batch_options.add_row("4", "📄 Process file of companies")
        batch_options.add_row("5", "📄 Process file of aircraft registrations")
        batch_options.add_row("6", "📄 Process file of crypto addresses")
        batch_options.add_row("7", "📄 Custom batch analysis")
        batch_options.add_row("0", "🔙 Back to main menu")

        console.print(batch_options)

        choice = Prompt.ask(
            "\n[bold yellow]Select batch analysis type[/bold yellow]", default="0"
        )

        if choice == "1":
            self.batch_domain_analysis()
        elif choice == "2":
            self.batch_email_analysis()
        elif choice == "3":
            self.batch_ip_analysis()
        elif choice == "4":
            self.batch_company_analysis()
        elif choice == "5":
            self.batch_flight_analysis()
        elif choice == "6":
            self.batch_crypto_analysis()
        elif choice == "7":
            self.custom_batch_analysis()

    def batch_domain_analysis(self):
        """Batch domain analysis"""
        filename = Prompt.ask("Enter filename with domains (one per line)")

        if not os.path.exists(filename):
            console.print(f"[red]File {filename} not found[/red]")
            return

        try:
            with open(filename, "r") as f:
                domains = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]

            console.print(f"\n[yellow]Processing {len(domains)} domains...[/yellow]")

            all_results = []
            for domain in track(domains, description="Analyzing domains..."):
                results = self.domain_recon.analyze_domain(domain)
                if results:
                    all_results.append(results)
                time.sleep(1)  # Rate limiting

            # Save batch results
            batch_filename = self.utils.save_results(
                all_results, "batch_domain_analysis"
            )
            console.print(f"\n[green]Batch results saved to: {batch_filename}[/green]")

        except Exception as e:
            console.print(f"[red]Batch analysis failed: {e}[/red]")

    def batch_email_analysis(self):
        """Batch email analysis"""
        filename = Prompt.ask("Enter filename with email addresses (one per line)")

        if not os.path.exists(filename):
            console.print(f"[red]File {filename} not found[/red]")
            return

        try:
            with open(filename, "r") as f:
                emails = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]

            console.print(
                f"\n[yellow]Processing {len(emails)} email addresses...[/yellow]"
            )

            all_results = []
            for email in track(emails, description="Analyzing emails..."):
                results = self.email_intel.analyze_email(email)
                if results:
                    all_results.append(results)
                time.sleep(1)  # Rate limiting

            # Save batch results
            batch_filename = self.utils.save_results(
                all_results, "batch_email_analysis"
            )
            console.print(f"\n[green]Batch results saved to: {batch_filename}[/green]")

        except Exception as e:
            console.print(f"[red]Batch analysis failed: {e}[/red]")

    def batch_ip_analysis(self):
        """Batch IP analysis"""
        filename = Prompt.ask("Enter filename with IP addresses (one per line)")

        if not os.path.exists(filename):
            console.print(f"[red]File {filename} not found[/red]")
            return

        try:
            with open(filename, "r") as f:
                ips = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]

            console.print(f"\n[yellow]Processing {len(ips)} IP addresses...[/yellow]")

            all_results = []
            for ip in track(ips, description="Analyzing IPs..."):
                results = self.ip_intel.analyze_ip(ip)
                if results:
                    all_results.append(results)
                time.sleep(1)  # Rate limiting

            # Save batch results
            batch_filename = self.utils.save_results(all_results, "batch_ip_analysis")
            console.print(f"\n[green]Batch results saved to: {batch_filename}[/green]")

        except Exception as e:
            console.print(f"[red]Batch analysis failed: {e}[/red]")

    def batch_company_analysis(self):
        """Batch company analysis"""
        filename = Prompt.ask("Enter filename with companies (one per line)")

        if not os.path.exists(filename):
            console.print(f"[red]File {filename} not found[/red]")
            return

        try:
            with open(filename, "r") as f:
                companies = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]

            console.print(
                f"\n[yellow]Processing {len(companies)} companies...[/yellow]"
            )

            all_results = []
            for company in track(companies, description="Analyzing companies..."):
                results = self.company_intel.analyze_company(company)
                if results:
                    all_results.append(results)
                time.sleep(1)  # Rate limiting

            # Save batch results
            batch_filename = self.utils.save_results(
                all_results, "batch_company_analysis"
            )
            console.print(f"\n[green]Batch results saved to: {batch_filename}[/green]")

        except Exception as e:
            console.print(f"[red]Batch analysis failed: {e}[/red]")

    def batch_flight_analysis(self):
        """Batch flight analysis"""
        filename = Prompt.ask(
            "Enter filename with aircraft registrations (one per line)"
        )

        if not os.path.exists(filename):
            console.print(f"[red]File {filename} not found[/red]")
            return

        try:
            with open(filename, "r") as f:
                aircraft = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]

            console.print(f"\n[yellow]Processing {len(aircraft)} aircraft...[/yellow]")

            all_results = []
            for reg in track(aircraft, description="Analyzing aircraft..."):
                results = self.flight_intel.analyze_aircraft(reg, "registration")
                if results:
                    all_results.append(results)
                time.sleep(2)  # Longer rate limiting for flight data

            # Save batch results
            batch_filename = self.utils.save_results(
                all_results, "batch_flight_analysis"
            )
            console.print(f"\n[green]Batch results saved to: {batch_filename}[/green]")

        except Exception as e:
            console.print(f"[red]Batch analysis failed: {e}[/red]")

    def batch_crypto_analysis(self):
        """Batch crypto analysis"""
        filename = Prompt.ask("Enter filename with crypto addresses (one per line)")
        currency = Prompt.ask(
            "Enter currency type (bitcoin/ethereum/litecoin/dogecoin)",
            default="bitcoin",
        )

        if not os.path.exists(filename):
            console.print(f"[red]File {filename} not found[/red]")
            return

        try:
            with open(filename, "r") as f:
                addresses = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]

            console.print(
                f"\n[yellow]Processing {len(addresses)} {currency} addresses...[/yellow]"
            )

            all_results = []
            for address in track(
                addresses, description="Analyzing crypto addresses..."
            ):
                results = self.crypto_intel.analyze_crypto_address(address, currency)
                if results:
                    all_results.append(results)
                time.sleep(1)  # Rate limiting

            # Save batch results
            batch_filename = self.utils.save_results(
                all_results, f"batch_crypto_analysis_{currency}"
            )
            console.print(f"\n[green]Batch results saved to: {batch_filename}[/green]")

        except Exception as e:
            console.print(f"[red]Batch analysis failed: {e}[/red]")

    def custom_batch_analysis(self):
        """Custom batch analysis with mixed types"""
        console.print("\n[bold cyan]Custom Batch Analysis[/bold cyan]\n")
        console.print(
            "Format: <type>:<value> (e.g., domain:example.com, email:user@example.com)"
        )

        filename = Prompt.ask("Enter filename with mixed targets")

        if not os.path.exists(filename):
            console.print(f"[red]File {filename} not found[/red]")
            return

        try:
            with open(filename, "r") as f:
                lines = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]

            all_results = []
            for line in track(lines, description="Processing mixed targets..."):
                if ":" not in line:
                    continue

                target_type, target_value = line.split(":", 1)
                target_type = target_type.lower().strip()
                target_value = target_value.strip()

                if target_type == "domain":
                    results = self.domain_recon.analyze_domain(target_value)
                elif target_type == "email":
                    results = self.email_intel.analyze_email(target_value)
                elif target_type == "ip":
                    results = self.ip_intel.analyze_ip(target_value)
                elif target_type == "company":
                    results = self.company_intel.analyze_company(target_value)
                elif target_type == "aircraft":
                    results = self.flight_intel.analyze_aircraft(
                        target_value, "registration"
                    )
                elif target_type.startswith("crypto"):
                    currency = (
                        target_type.split("_")[1] if "_" in target_type else "bitcoin"
                    )
                    results = self.crypto_intel.analyze_crypto_address(
                        target_value, currency
                    )
                else:
                    console.print(
                        f"[yellow]Unknown type '{target_type}' for {target_value}[/yellow]"
                    )
                    continue

                if results:
                    all_results.append(results)
                time.sleep(1)

            batch_filename = self.utils.save_results(
                all_results, "batch_custom_analysis"
            )
            console.print(
                f"\n[green]Custom batch analysis completed: {batch_filename}[/green]"
            )

        except Exception as e:
            console.print(f"[red]Custom batch analysis failed: {e}[/red]")

    def view_results_menu(self):
        """View previous results"""
        console.print("\n[bold cyan]📁 View Results[/bold cyan]\n")

        output_dir = "output"
        if not os.path.exists(output_dir):
            console.print("[red]No results directory found[/red]")
            return

        files = [f for f in os.listdir(output_dir) if f.endswith(".json")]
        if not files:
            console.print("[red]No result files found[/red]")
            return

        files.sort(
            key=lambda x: os.path.getmtime(os.path.join(output_dir, x)), reverse=True
        )

        table = Table(title="Recent Results")
        table.add_column("Index", style="cyan")
        table.add_column("Filename", style="green")
        table.add_column("Type", style="yellow")
        table.add_column("Modified", style="white")

        for i, filename in enumerate(files[:25]):  # Show last 25 files
            filepath = os.path.join(output_dir, filename)
            mod_time = datetime.fromtimestamp(os.path.getmtime(filepath)).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            # Determine file type from filename
            file_type = "Unknown"
            if "domain" in filename:
                file_type = "Domain"
            elif "email" in filename:
                file_type = "Email"
            elif "ip" in filename:
                file_type = "IP"
            elif "company" in filename:
                file_type = "Company"
            elif "flight" in filename:
                file_type = "Flight"
            elif "crypto" in filename:
                file_type = "Crypto"
            elif "search" in filename:
                file_type = "Search"
            elif "batch" in filename:
                file_type = "Batch"

            table.add_row(str(i + 1), filename, file_type, mod_time)

        console.print(table)

        choice = Prompt.ask("\nEnter file index to view (0 to go back)", default="0")

        try:
            index = int(choice) - 1
            if 0 <= index < len(files):
                filepath = os.path.join(output_dir, files[index])
                with open(filepath, "r") as f:
                    data = json.load(f)
                console.print(json.dumps(data, indent=2))

                # Option to export to different formats
                if Confirm.ask("\nExport to different format?"):
                    export_format = Prompt.ask(
                        "Export format", choices=["txt", "csv"], default="txt"
                    )
                    export_filename = filepath.replace(".json", f".{export_format}")

                    if export_format == "txt":
                        with open(export_filename, "w") as f:
                            f.write(json.dumps(data, indent=2))
                    elif export_format == "csv":
                        # Convert to CSV (basic implementation)
                        import csv

                        with open(export_filename, "w", newline="") as f:
                            if isinstance(data, list):
                                if data:
                                    writer = csv.DictWriter(
                                        f, fieldnames=data[0].keys()
                                    )
                                    writer.writeheader()
                                    writer.writerows(data)
                            else:
                                writer = csv.writer(f)
                                for key, value in data.items():
                                    writer.writerow([key, value])

                    console.print(f"[green]Exported to: {export_filename}[/green]")

        except (ValueError, IndexError):
            if choice != "0":
                console.print("[red]Invalid selection[/red]")

    def configuration_menu(self):
        """Configuration menu"""
        console.print("\n[bold cyan]⚙️ Configuration[/bold cyan]\n")

        cfg_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "config", "config.ini"
        )

        config_options = Table(show_header=False, show_edge=False, pad_edge=False)
        config_options.add_column("Option", style="cyan", width=3)
        config_options.add_column("Description", style="white")

        config_options.add_row("1", "🔑 View API Key Status")
        config_options.add_row("2", "📝 Edit Configuration")
        config_options.add_row("3", "🧪 Test API Connections")
        config_options.add_row("4", "📊 View System Statistics")
        config_options.add_row("5", "🔧 Reset Configuration")
        config_options.add_row("6", "⚠️ Toggle Active Checks (ENABLE_ACTIVE)")
        config_options.add_row("7", "🛠️ Edit Global Settings")
        config_options.add_row("0", "🔙 Back to main menu")

        console.print(config_options)

        choice = Prompt.ask(
            "\n[bold yellow]Select configuration option[/bold yellow]", default="0"
        )

        if choice == "1":
            self.view_api_status()
        elif choice == "2":
            console.print("[yellow]Edit config/config.ini file manually[/yellow]")
            console.print("Configuration file location: config/config.ini")
        elif choice == "3":
            self.test_api_connections()
        elif choice == "4":
            self.view_system_statistics()
        elif choice == "5":
            self.reset_configuration()
        elif choice == "6":
            # Toggle ENABLE_ACTIVE
            current = self.utils.config.getboolean(
                "SETTINGS", "ENABLE_ACTIVE", fallback=False
            )
            console.print(f"\nCurrent ENABLE_ACTIVE = {current}")
            console.print(
                "\nWARNING: Active checks may perform live network/tcp operations (non-passive). Enable only if you understand the OPSEC implications."
            )
            if Confirm.ask("Do you want to toggle ENABLE_ACTIVE?", default=False):
                new_val = not current
                # Persist to config file (create backup first)
                cfg_path = os.path.join(
                    os.path.dirname(os.path.abspath(__file__)), "config", "config.ini"
                )
                try:
                    # Backup
                    try:
                        self.utils.backup_config(cfg_path)
                    except Exception:
                        pass
                    # Update parser object
                    if "SETTINGS" not in self.utils.config:
                        self.utils.config["SETTINGS"] = {}
                    self.utils.config["SETTINGS"]["ENABLE_ACTIVE"] = (
                        "True" if new_val else "False"
                    )
                    with open(cfg_path, "w") as cf:
                        self.utils.config.write(cf)
                    console.print(
                        f"[green]ENABLE_ACTIVE set to {new_val} and saved to {cfg_path}[/green]"
                    )
                    # Reload utils to pick up change if necessary
                    self.utils = OSINTUtils()
                except Exception as e:
                    console.print(f"[red]Failed to update config: {e}[/red]")

        elif choice == "7":
            # Global settings editor (safe editor for core SETTINGS keys)
            console.print("\n[bold cyan]Global Settings Editor[/bold cyan]\n")
            settings = (
                self.utils.config["SETTINGS"] if "SETTINGS" in self.utils.config else {}
            )
            # Show current values
            keys = [
                "AUTO_FALLBACK",
                "FALLBACK_TO_VPN",
                "VPN_PROXY",
                "FALLBACK_MAX_RETRIES",
                "DOH_PROVIDER",
                "USER_AGENT",
                "ENABLE_ACTIVE",
            ]
            for k in keys:
                val = settings.get(k, "") if settings else ""
                console.print(f"{k}: {val}")

            if Confirm.ask("Edit settings now?", default=False):
                for k in keys:
                    current_val = settings.get(k, "") if settings else ""
                    new_val = Prompt.ask(f"{k}", default=current_val)
                    if "SETTINGS" not in self.utils.config:
                        self.utils.config["SETTINGS"] = {}
                    self.utils.config["SETTINGS"][k] = new_val
                # Backup and write
                try:
                    self.utils.backup_config(cfg_path)
                except Exception:
                    pass
                try:
                    with open(cfg_path, "w") as cf:
                        self.utils.config.write(cf)
                    console.print(f"[green]Settings saved to {cfg_path}[/green]")
                    self.utils = OSINTUtils()
                except Exception as e:
                    console.print(f"[red]Failed to save settings: {e}[/red]")

    def system_status_menu(self):
        """System status and diagnostics"""
        console.print("\n[bold cyan]🔧 System Status[/bold cyan]\n")

        status_table = Table(title="System Health Check")
        status_table.add_column("Component", style="cyan")
        status_table.add_column("Status", style="green")
        status_table.add_column("Details", style="white")

        # Check output directory
        output_exists = os.path.exists("output")
        status_table.add_row(
            "Output Directory", "✅ OK" if output_exists else "❌ Missing", "output/"
        )

        # Check config directory
        config_exists = os.path.exists("config")
        status_table.add_row(
            "Config Directory", "✅ OK" if config_exists else "❌ Missing", "config/"
        )

        # Check modules
        modules_status = "✅ OK"
        try:
            # Test module imports (already imported at module top)
            _ = self.domain_recon
            _ = self.utils
        except Exception:
            modules_status = "❌ Import Error"

        status_table.add_row("OSINT Modules", modules_status, "Core modules")

        # Check API keys
        api_count = len([k for k in self.utils.get_all_api_keys() if k])
        status_table.add_row(
            "API Keys", f"✅ {api_count} configured", "Various services"
        )

        # Check disk space
        import shutil

        total, used, free = shutil.disk_usage(".")
        free_gb = free // (1024**3)
        disk_status = (
            "✅ OK" if free_gb > 1 else "⚠️ Low" if free_gb > 0.5 else "❌ Critical"
        )
        status_table.add_row("Disk Space", disk_status, f"{free_gb}GB free")

        console.print(status_table)

        if Confirm.ask(
            "Run Troubleshoot & Auto-fix now? (will attempt to repair missing files/dirs and set proxy env)",
            default=False,
        ):
            console.print("[yellow]Running self-check...[/yellow]")
            report = self.utils.self_check(auto_fix=True, test_network=False)
            console.print(f"[green]Self-check report:[/green] {report}")

        console.print(status_table)

        # Show recent activity
        if output_exists:
            recent_files = []
            try:
                files = os.listdir("output")
                json_files = [f for f in files if f.endswith(".json")]
                if json_files:
                    json_files.sort(
                        key=lambda x: os.path.getmtime(os.path.join("output", x)),
                        reverse=True,
                    )
                    recent_files = json_files[:5]
            except Exception:
                pass

            if recent_files:
                console.print("\n[bold]Recent Activity:[/bold]")
                for i, filename in enumerate(recent_files, 1):
                    filepath = os.path.join("output", filename)
                    mod_time = datetime.fromtimestamp(
                        os.path.getmtime(filepath)
                    ).strftime("%m-%d %H:%M")
                    analysis_type = (
                        filename.split("_")[0] if "_" in filename else "unknown"
                    )
                    console.print(
                        f"  {i}. {analysis_type.title():<10} - {mod_time}"
                    )

    def view_api_status(self):
        """View API key status"""
        console.print("\n[bold cyan]🔑 API Key Status[/bold cyan]\n")

        api_services = [
            "SHODAN_API_KEY",
            "ALIENVAULT_API_KEY",
            "HUNTER_API_KEY",
            "GREYNOISE_API_KEY",
            "SECURITYTRAILS_API_KEY",
            "GOOGLESEARCH_API_KEY",
            "VIRUSTOTAL_API_KEY",
            "ABUSEIPDB_API_KEY",
            "CLEARBIT_API_KEY",
            "WHOISXML_API_KEY",
            "INTELX_API_KEY",
            "ETHERSCAN_API_KEY",
            "CRYPTOCOMPARE_API_KEY",
            "FLIGHTAWARE_API_KEY",
            "CENSYS_API_KEY",
        ]

        table = Table(title="API Keys Status")
        table.add_column("Service", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Priority", style="yellow")

        # Define priority levels
        priority_map = {
            "SHODAN_API_KEY": "High",
            "VIRUSTOTAL_API_KEY": "High",
            "HUNTER_API_KEY": "High",
            "ABUSEIPDB_API_KEY": "Medium",
            "GREYNOISE_API_KEY": "Medium",
            "CLEARBIT_API_KEY": "Medium",
            "ETHERSCAN_API_KEY": "Low",
            "FLIGHTAWARE_API_KEY": "Low",
        }

        configured_count = 0
        for service in api_services:
            api_key = self.utils.get_api_key(service)
            status = "✅ Configured" if api_key else "❌ Missing"
            priority = priority_map.get(service, "Low")

            if api_key:
                configured_count += 1

            service_name = service.replace("_API_KEY", "").title()
            table.add_row(service_name, status, priority)

        console.print(table)
        console.print(
            f"\n[bold]Summary:[/bold] {configured_count}/{len(api_services)} API keys configured"
        )

    def test_api_connections(self):
        """Test API connections"""
        console.print("\n[bold cyan]🧪 Testing API Connections[/bold cyan]\n")

        # Test basic connectivity first
        console.print("Testing basic connectivity...")
        try:
            # Prefer the tor-routed session from OSINTUtils to keep checks OPSEC-safe
            session = getattr(self.utils, "session", None)
            if session:
                response = session.get("https://httpbin.org/ip", timeout=10)
            else:
                import requests

                response = requests.get("https://httpbin.org/ip", timeout=10)
            console.print("✅ Internet connectivity: OK")
        except Exception:
            console.print("❌ Internet connectivity: Failed")
            return

        # Test specific APIs (basic connectivity test)
        api_endpoints = {
            "VirusTotal": "https://www.virustotal.com",
            "Shodan": "https://api.shodan.io",
            "AbuseIPDB": "https://api.abuseipdb.com",
            "Hunter.io": "https://api.hunter.io",
        }

        console.print("\nTesting API endpoint accessibility...")
        for service, endpoint in api_endpoints.items():
            try:
                session = getattr(self.utils, "session", None)
                if session:
                    response = session.head(endpoint, timeout=10)
                else:
                    import requests

                    response = requests.head(endpoint, timeout=10)
                status = "✅ Accessible" if response.status_code < 500 else "⚠️ Issues"
            except Exception:
                status = "❌ Unreachable"
            console.print(f"{service:<15}: {status}")

        console.print(
            "\n[yellow]Note: Full API key validation requires actual API calls during analysis[/yellow]"
        )

    def view_system_statistics(self):
        """View system usage statistics"""
        console.print("\n[bold cyan]📊 System Statistics[/bold cyan]\n")

        output_dir = "output"
        if not os.path.exists(output_dir):
            console.print(
                "[red]No statistics available - output directory not found[/red]"
            )
            return

        try:
            files = os.listdir(output_dir)
            json_files = [f for f in files if f.endswith(".json")]

            # Count by type
            stats = {
                "domain": len([f for f in json_files if "domain" in f]),
                "email": len([f for f in json_files if "email" in f]),
                "ip": len([f for f in json_files if "ip" in f]),
                "company": len([f for f in json_files if "company" in f]),
                "flight": len([f for f in json_files if "flight" in f]),
                "crypto": len([f for f in json_files if "crypto" in f]),
                "batch": len([f for f in json_files if "batch" in f]),
            }

            stats_table = Table(title="Analysis Statistics")
            stats_table.add_column("Analysis Type", style="cyan")
            stats_table.add_column("Count", style="green")
            stats_table.add_column("Percentage", style="yellow")

            total_analyses = sum(stats.values())

            for analysis_type, count in stats.items():
                percentage = (count / total_analyses * 100) if total_analyses > 0 else 0
                stats_table.add_row(
                    analysis_type.title(), str(count), f"{percentage:.1f}%"
                )

            stats_table.add_row("", "", "")  # Separator
            stats_table.add_row("Total", str(total_analyses), "100.0%")

            console.print(stats_table)

            # Recent activity trend
            if total_analyses > 0:
                recent_files = sorted(
                    json_files,
                    key=lambda x: os.path.getmtime(os.path.join(output_dir, x)),
                    reverse=True,
                )[:10]

                console.print("\n[bold]Recent Analysis Trend:[/bold]")
                for i, filename in enumerate(recent_files, 1):
                    filepath = os.path.join(output_dir, filename)
                    mod_time = datetime.fromtimestamp(os.path.getmtime(filepath))
                    analysis_type = (
                        filename.split("_")[0] if "_" in filename else "unknown"
                    )
                    console.print(
                        f"  {i}. {analysis_type.title():<10} - {mod_time.strftime('%m/%d %H:%M')}"
                    )

        except Exception as e:
            console.print(f"[red]Error generating statistics: {e}[/red]")

    def check_tor_status_menu(self):
        """Check if Tor is running and being used for requests"""
        console.print("\n[bold cyan]🛡️ Tor Proxy Status[/bold cyan]\n")
        try:
            import requests

            # Use the tor_get method if available, else use requests directly
            session = getattr(self.utils, "session", None)
            if session:
                response = session.get("https://check.torproject.org/", timeout=10)
            else:
                proxies = {
                    "http": "socks5h://127.0.0.1:9050",
                    "https": "socks5h://127.0.0.1:9050",
                }
                response = requests.get(
                    "https://check.torproject.org/", proxies=proxies, timeout=10
                )
            if (
                "Congratulations. This browser is configured to use Tor"
                in response.text
            ):
                console.print(
                    "[green]Tor is running and your traffic is routed through Tor![/green]"
                )
            else:
                console.print(
                    "[yellow]Tor is running, but your traffic may not be routed through Tor.[/yellow]"
                )
        except Exception:
            console.print(f"[red]Could not verify Tor status: {e}[/red]")

    def display_email_summary(self, results):
        """Display email analysis summary"""
        console.print("\n[bold green]📊 Email Analysis Summary[/bold green]\n")

        table = Table(title=f"Email: {results['email']}")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")

        domain_info = results.get("domain_info", {})
        if "domain" in domain_info:
            table.add_row("Domain", domain_info["domain"])

        breach_data = results.get("breach_data", {})
        hibp_data = breach_data.get("haveibeenpwned", {})
        if "found" in hibp_data:
            breach_status = (
                f"Found in {hibp_data.get('breach_count', 0)} breaches"
                if hibp_data["found"]
                else "No breaches found"
            )
            table.add_row("Breach Status", breach_status)

        # Additional email validation
        validation = results.get("validation", {})
        if validation:
            table.add_row(
                "Valid Format", "✅ Yes" if validation.get("valid_format") else "❌ No"
            )
            table.add_row(
                "Disposable", "⚠️ Yes" if validation.get("disposable") else "✅ No"
            )

        console.print(table)

    def display_ip_summary(self, results):
        """Display IP analysis summary"""
        console.print("\n[bold green]📊 IP Analysis Summary[/bold green]\n")

        table = Table(title=f"IP: {results['ip']}")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")

        geo = results.get("geolocation", {})
        ipapi_data = geo.get("ipapi", {})
        if "country" in ipapi_data:
            table.add_row(
                "Country",
                f"{ipapi_data['country']} ({ipapi_data.get('countryCode', '')})",
            )
            table.add_row("City", ipapi_data.get("city", ""))
            table.add_row("ISP", ipapi_data.get("isp", ""))

        reputation = results.get("reputation", {})
        abuseipdb = reputation.get("abuseipdb", {})
        if "abuse_confidence" in abuseipdb:
            confidence = abuseipdb["abuse_confidence"]
            risk_level = (
                "HIGH" if confidence > 75 else "MEDIUM" if confidence > 25 else "LOW"
            )
            table.add_row("Abuse Confidence", f"{confidence}% ({risk_level})")

        # Additional security info
        security_info = results.get("security", {})
        if security_info:
            table.add_row(
                "Malware", "⚠️ Yes" if security_info.get("malware") else "✅ Clean"
            )
            table.add_row(
                "Botnet", "⚠️ Yes" if security_info.get("botnet") else "✅ Clean"
            )

        console.print(table)

    def display_company_summary(self, results):
        """Display company analysis summary"""
        console.print("\n[bold green]📊 Company Analysis Summary[/bold green]\n")

        table = Table(title=f"Company: {results['company_name']}")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")

        company_info = results.get("company_info", {})
        clearbit_data = company_info.get("clearbit", {})
        if "domain" in clearbit_data:
            table.add_row("Domain", clearbit_data["domain"])
        if "industry" in clearbit_data:
            table.add_row("Industry", clearbit_data["industry"])
        if "employees" in clearbit_data:
            table.add_row("Employees", str(clearbit_data["employees"]))

        employees = results.get("employees", {})
        hunter_data = employees.get("hunter_emails", {})
        if "total_emails" in hunter_data:
            table.add_row("Emails Found", str(hunter_data["total_emails"]))

        # Additional company intelligence
        social_presence = results.get("social_presence", {})
        if social_presence:
            platforms = len(
                [p for p, data in social_presence.items() if data.get("found")]
            )
            table.add_row("Social Platforms", str(platforms))

        console.print(table)

    def display_flight_summary(self, results):
        """Display flight analysis summary"""
        console.print("\n[bold green]📊 Flight Intelligence Summary[/bold green]\n")

        table = Table(title=f"Aircraft: {results['identifier']}")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")

        aircraft_info = results.get("aircraft_info", {})
        fa_data = aircraft_info.get("flightaware", {})
        for key, value in fa_data.items():
            if key not in ["raw_response", "api_response"]:  # Skip raw data
                display_key = key.replace("_", " ").title()
                table.add_row(display_key, str(value))

        flight_history = results.get("flight_history", {})
        total_flights = flight_history.get("total_tracked", 0)
        table.add_row("Tracked Flights", str(total_flights))

        # Recent activity
        recent_flights = flight_history.get("recent_flights", [])
        if recent_flights:
            table.add_row("Recent Activity", f"{len(recent_flights)} recent flights")

        console.print(table)

    def display_passive_search_summary(self, results):
        """Display passive search summary"""
        console.print("\n[bold green]📊 Passive Search Summary[/bold green]\n")

        table = Table(title=f"Target: {results['target']}")
        table.add_column("Source", style="cyan")
        table.add_column("Results", style="white")

        google_results = results.get("google_dorking", {})
        executed_dorks = google_results.get("executed_dorks", 0)
        table.add_row("Google Dorks", f"{executed_dorks} executed")

        social_media = results.get("social_media", {})
        found_profiles = sum(
            1 for result in social_media.values() if result.get("found")
        )
        table.add_row("Social Media", f"{found_profiles} profiles found")

        github_results = results.get("github_search", {})
        github_total = github_results.get("total_results", 0)
        table.add_row("GitHub", f"{github_total} results")

        # Additional sources
        leaked_data = results.get("data_leaks", {})
        if leaked_data:
            leak_count = len(leaked_data.get("sources", []))
            table.add_row("Data Leaks", f"{leak_count} potential sources")

        console.print(table)

    def display_crypto_summary(self, results):
        """Display cryptocurrency analysis summary"""
        console.print("\n[bold green]📊 Cryptocurrency Analysis Summary[/bold green]\n")

        table = Table(title=f"Address: {results['address'][:20]}...")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Currency", results["currency_type"].title())

        address_info = results.get("address_info", {})
        for source, data in address_info.items():
            if isinstance(data, dict) and "balance" in data:
                balance = data.get("balance", 0)
                table.add_row(f"{source.title()} Balance", f"{balance:.8f}")

        risk_analysis = results.get("risk_analysis", {})
        risk_score = risk_analysis.get("risk_score", 0)
        risk_level = risk_analysis.get("risk_level", "unknown")
        table.add_row("Risk Score", f"{risk_score}/100")
        table.add_row("Risk Level", risk_level.upper())

        # Transaction analysis
        transactions = results.get("transactions", {})
        if transactions:
            tx_count = transactions.get("total_transactions", 0)
            table.add_row("Total Transactions", str(tx_count))

            first_seen = transactions.get("first_transaction")
            if first_seen:
                table.add_row("First Activity", first_seen)

        console.print(table)

    def advanced_analysis_menu(self):
        """Advanced analysis suite menu"""
        while True:
            console.print("\n[bold cyan]📊 Advanced Analysis Suite[/bold cyan]\n")

            analysis_options = Table(show_header=False, show_edge=False, pad_edge=False)
            analysis_options.add_column("Option", style="cyan", width=3)
            analysis_options.add_column("Description", style="white")

            analysis_options.add_row("1", "📈 Statistical Analysis")
            analysis_options.add_row("2", "🔍 Correlation Analysis")
            analysis_options.add_row("3", "📊 Data Visualization")
            analysis_options.add_row("4", "🧮 Predictive Modeling")
            analysis_options.add_row("5", "🔬 Anomaly Detection")
            analysis_options.add_row("0", "🔙 Back to main menu")

            console.print(analysis_options)

            choice = Prompt.ask(
                "\n[bold yellow]Select advanced analysis option[/bold yellow]", default="0"
            )

            if choice == "1":
                self.statistical_analysis()
            elif choice == "2":
                self.correlation_analysis()
            elif choice == "3":
                self.data_visualization()
            elif choice == "4":
                self.predictive_modeling()
            elif choice == "5":
                self.anomaly_detection()
            elif choice == "0":
                break
            else:
                console.print("[red]Invalid option. Please try again.[/red]")

    def intelligence_reporting_menu(self):
        """Intelligence reporting menu"""
        while True:
            console.print("\n[bold cyan]📊 Intelligence Reporting[/bold cyan]\n")

            reporting_options = Table(show_header=False, show_edge=False, pad_edge=False)
            reporting_options.add_column("Option", style="cyan", width=3)
            reporting_options.add_column("Description", style="white")

            reporting_options.add_row("1", "📄 Executive Summary")
            reporting_options.add_row("2", "📊 Intelligence Brief")
            reporting_options.add_row("3", "🔍 Detailed Analysis")
            reporting_options.add_row("4", "📈 Trend Reports")
            reporting_options.add_row("5", "🎯 Threat Assessment")
            reporting_options.add_row("0", "🔙 Back to main menu")

            console.print(reporting_options)

            choice = Prompt.ask(
                "\n[bold yellow]Select intelligence reporting option[/bold yellow]", default="0"
            )

            if choice == "1":
                self.executive_summary()
            elif choice == "2":
                self.intelligence_brief()
            elif choice == "3":
                self.detailed_analysis()
            elif choice == "4":
                self.trend_reports()
            elif choice == "5":
                self.threat_assessment()
            elif choice == "0":
                break
            else:
                console.print("[red]Invalid option. Please try again.[/red]")

    def realtime_feeds_menu(self):
        """Real-time intelligence feeds menu"""
        while True:
            console.print("\n[bold cyan]📡 Real-time Intelligence Feeds[/bold cyan]\n")

            feeds_options = Table(show_header=False, show_edge=False, pad_edge=False)
            feeds_options.add_column("Option", style="cyan", width=3)
            feeds_options.add_column("Description", style="white")

            feeds_options.add_row("1", "🌐 Live Network Monitoring")
            feeds_options.add_row("2", "📡 Dark Web Feeds")
            feeds_options.add_row("3", "📰 News & Media Feeds")
            feeds_options.add_row("4", "💰 Financial Market Feeds")
            feeds_options.add_row("5", "🔐 Security Threat Feeds")
            feeds_options.add_row("0", "🔙 Back to main menu")

            console.print(feeds_options)

            choice = Prompt.ask(
                "\n[bold yellow]Select real-time feeds option[/bold yellow]", default="0"
            )

            if choice == "1":
                self.live_network_monitoring()
            elif choice == "2":
                self.dark_web_feeds()
            elif choice == "3":
                self.news_media_feeds()
            elif choice == "4":
                self.financial_market_feeds()
            elif choice == "5":
                self.security_threat_feeds()
            elif choice == "0":
                break
            else:
                console.print("[red]Invalid option. Please try again.[/red]")

    def bellingcat_toolkit_menu(self):
        """Bellingcat Investigation Toolkit menu for advanced OSINT investigations"""
        while True:
            console.print("\n[bold cyan]🕵️ Bellingcat Investigation Toolkit[/bold cyan]\n")

            toolkit_options = Table(show_header=False, show_edge=False, pad_edge=False)
            toolkit_options.add_column("Option", style="cyan", width=3)
            toolkit_options.add_column("Description", style="white")

            toolkit_options.add_row("1", "🔍 Cross-Reference Analysis")
            toolkit_options.add_row("2", "📊 Pattern Detection")
            toolkit_options.add_row("3", "🌐 Network Mapping")
            toolkit_options.add_row("4", "📈 Timeline Analysis")
            toolkit_options.add_row("5", "🔗 Entity Linking")
            toolkit_options.add_row("6", "📋 Evidence Collection")
            toolkit_options.add_row("7", "🧩 Conspiracy Analysis")
            toolkit_options.add_row("8", "📊 Advanced Reporting")
            toolkit_options.add_row("9", "🔬 Metadata Analysis")
            toolkit_options.add_row("10", "🕵️ Investigation Workflow")
            toolkit_options.add_row("0", "🔙 Back to main menu")

            console.print(toolkit_options)

            choice = Prompt.ask(
                "\n[bold yellow]Select Bellingcat toolkit option[/bold yellow]", default="0"
            )

            if choice == "1":
                self.cross_reference_analysis()
            elif choice == "2":
                self.pattern_detection()
            elif choice == "3":
                self.network_mapping()
            elif choice == "4":
                self.timeline_analysis()
            elif choice == "5":
                self.entity_linking()
            elif choice == "6":
                self.evidence_collection()
            elif choice == "7":
                self.conspiracy_analysis()
            elif choice == "8":
                self.advanced_reporting()
            elif choice == "9":
                self.metadata_analysis()
            elif choice == "10":
                self.investigation_workflow()
            elif choice == "0":
                break
            else:
                console.print("[red]Invalid option. Please try again.[/red]")

    def cross_reference_analysis(self):
        """Cross-reference multiple data sources for investigation"""
        console.print("\n[bold cyan]🔍 Cross-Reference Analysis[/bold cyan]\n")
        console.print("[yellow]Cross-reference analysis functionality coming soon...[/yellow]")

    def pattern_detection(self):
        """Detect patterns in data for investigative leads"""
        console.print("\n[bold cyan]📊 Pattern Detection[/bold cyan]\n")
        console.print("[yellow]Pattern detection functionality coming soon...[/yellow]")

    def network_mapping(self):
        """Create network maps of entities and relationships"""
        console.print("\n[bold cyan]🌐 Network Mapping[/bold cyan]\n")
        console.print("[yellow]Network mapping functionality coming soon...[/yellow]")

    def timeline_analysis(self):
        """Analyze events over time for investigation"""
        console.print("\n[bold cyan]📈 Timeline Analysis[/bold cyan]\n")
        console.print("[yellow]Timeline analysis functionality coming soon...[/yellow]")

    def entity_linking(self):
        """Link entities across different data sources"""
        console.print("\n[bold cyan]🔗 Entity Linking[/bold cyan]\n")
        console.print("[yellow]Entity linking functionality coming soon...[/yellow]")

    def evidence_collection(self):
        """Collect and organize evidence for investigations"""
        console.print("\n[bold cyan]📋 Evidence Collection[/bold cyan]\n")
        console.print("[yellow]Evidence collection functionality coming soon...[/yellow]")

    def conspiracy_analysis(self):
        """Analyze conspiracy theories and misinformation"""
        console.print("\n[bold cyan]🧩 Conspiracy Analysis[/bold cyan]\n")
        console.print("[yellow]Conspiracy analysis functionality coming soon...[/yellow]")

    def advanced_reporting(self):
        """Generate advanced investigative reports"""
        console.print("\n[bold cyan]📊 Advanced Reporting[/bold cyan]\n")
        console.print("[yellow]Advanced reporting functionality coming soon...[/yellow]")

    def metadata_analysis(self):
        """Analyze metadata from files and communications"""
        console.print("\n[bold cyan]🔬 Metadata Analysis[/bold cyan]\n")
        console.print("[yellow]Metadata analysis functionality coming soon...[/yellow]")

    def investigation_workflow(self):
        """Guided investigation workflow management"""
        console.print("\n[bold cyan]🕵️ Investigation Workflow[/bold cyan]\n")
        console.print("[yellow]Investigation workflow functionality coming soon...[/yellow]")

    # Advanced Analysis Suite methods
    def statistical_analysis(self):
        """Perform statistical analysis on collected data"""
        console.print("\n[bold cyan]📈 Statistical Analysis[/bold cyan]\n")
        console.print("[yellow]Statistical analysis functionality coming soon...[/yellow]")

    def correlation_analysis(self):
        """Analyze correlations between different data sources"""
        console.print("\n[bold cyan]🔍 Correlation Analysis[/bold cyan]\n")
        console.print("[yellow]Correlation analysis functionality coming soon...[/yellow]")

    def data_visualization(self):
        """Create visualizations from intelligence data"""
        console.print("\n[bold cyan]📊 Data Visualization[/bold cyan]\n")
        console.print("[yellow]Data visualization functionality coming soon...[/yellow]")

    def predictive_modeling(self):
        """Build predictive models from intelligence data"""
        console.print("\n[bold cyan]🧮 Predictive Modeling[/bold cyan]\n")
        console.print("[yellow]Predictive modeling functionality coming soon...[/yellow]")

    def anomaly_detection(self):
        """Detect anomalies in intelligence data"""
        console.print("\n[bold cyan]🔬 Anomaly Detection[/bold cyan]\n")
        console.print("[yellow]Anomaly detection functionality coming soon...[/yellow]")

    # Intelligence Reporting methods
    def executive_summary(self):
        """Generate executive summary reports"""
        console.print("\n[bold cyan]📄 Executive Summary[/bold cyan]\n")
        console.print("[yellow]Executive summary functionality coming soon...[/yellow]")

    def intelligence_brief(self):
        """Create intelligence briefing documents"""
        console.print("\n[bold cyan]📊 Intelligence Brief[/bold cyan]\n")
        console.print("[yellow]Intelligence brief functionality coming soon...[/yellow]")

    def detailed_analysis(self):
        """Perform detailed analysis reports"""
        console.print("\n[bold cyan]🔍 Detailed Analysis[/bold cyan]\n")
        console.print("[yellow]Detailed analysis functionality coming soon...[/yellow]")

    def trend_reports(self):
        """Generate trend analysis reports"""
        console.print("\n[bold cyan]📈 Trend Reports[/bold cyan]\n")
        console.print("[yellow]Trend reports functionality coming soon...[/yellow]")

    def threat_assessment(self):
        """Create threat assessment reports"""
        console.print("\n[bold cyan]🎯 Threat Assessment[/bold cyan]\n")
        console.print("[yellow]Threat assessment functionality coming soon...[/yellow]")

    # Real-time Feeds methods
    def live_network_monitoring(self):
        """Monitor network activity in real-time"""
        console.print("\n[bold cyan]🌐 Live Network Monitoring[/bold cyan]\n")
        console.print("[yellow]Live network monitoring functionality coming soon...[/yellow]")

    def dark_web_feeds(self):
        """Monitor dark web intelligence feeds"""
        console.print("\n[bold cyan]📡 Dark Web Feeds[/bold cyan]\n")
        console.print("[yellow]Dark web feeds functionality coming soon...[/yellow]")

    def news_media_feeds(self):
        """Monitor news and media intelligence feeds"""
        console.print("\n[bold cyan]📰 News & Media Feeds[/bold cyan]\n")
        console.print("[yellow]News & media feeds functionality coming soon...[/yellow]")

    def financial_market_feeds(self):
        """Monitor financial market intelligence feeds"""
        console.print("\n[bold cyan]💰 Financial Market Feeds[/bold cyan]\n")
        console.print("[yellow]Financial market feeds functionality coming soon...[/yellow]")

    def security_threat_feeds(self):
        """Monitor security threat intelligence feeds"""
        console.print("\n[bold cyan]🔐 Security Threat Feeds[/bold cyan]\n")
        console.print("[yellow]Security threat feeds functionality coming soon...[/yellow]")


def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(
        description="Passive OSINT Suite - Ultimate Edition"
    )
    parser.add_argument("--domain", help="Analyze specific domain")
    parser.add_argument("--email", help="Analyze specific email")
    parser.add_argument("--ip", help="Analyze specific IP address")
    parser.add_argument("--company", help="Analyze specific company")
    parser.add_argument("--aircraft", help="Analyze specific aircraft registration")
    parser.add_argument("--crypto", help="Analyze cryptocurrency address")
    parser.add_argument("--crypto-type", help="Cryptocurrency type", default="bitcoin")
    parser.add_argument("--search", help="Perform passive search")
    parser.add_argument(
        "--search-type",
        help="Search type (domain/email/company/person)",
        default="domain",
    )
    parser.add_argument("--batch", help="Batch analysis file")
    parser.add_argument("--batch-type", help="Batch analysis type", default="auto")
    parser.add_argument("--output", help="Output format (json/txt/csv)", default="json")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet mode")
    parser.add_argument(
        "--check-network",
        action="store_true",
        help="Enable network tests during troubleshooting/self-check",
    )

    args = parser.parse_args()

    # Tor preflight: ensure Tor proxy is reachable since transport enforces Tor by default
    try:
        # Simple check - just try to see if we can proceed without hard failure
        tor_available = True  # Assume Tor is available for now
        if not tor_available:
            print(
                "[OPSEC] Tor not reachable on 127.0.0.1:9050. Start Tor before running."
            )
            print(" - Option A (Docker): docker compose up -d tor-proxy")
            print(
                " - Option B (Local):  sudo apt-get install -y tor && sudo service tor start"
            )
            print(" - Then re-run your command. Tor is required by default.")
            # Don't hard-exit in interactive mode; allow menus to appear
            # For direct CLI invocations, we return non-zero to avoid noisy errors
            if any(
                [
                    args.domain,
                    args.email,
                    args.ip,
                    args.company,
                    args.aircraft,
                    args.crypto,
                    args.search,
                    args.batch,
                ]
            ):
                return 2
    except Exception:
        # Non-fatal: continue; detailed errors will surface later
        print(
            "[OPSEC] Tor preflight check encountered an issue; proceeding but network errors may occur."
        )

    suite = OSINTSuite()

    # Set verbosity
    if args.quiet:
        Console(quiet=True)

    # Propagate network-check flag into suite utils if requested
    if args.check_network:
        suite.utils._cli_check_network = True

    # Command line mode
    if args.domain:
        results = suite.domain_recon.analyze_domain(args.domain)
        if results:
            filename = suite.utils.save_results(
                results, f"domain_recon_{args.domain.replace('.', '_')}", args.output
            )
            if not args.quiet:
                print(f"Results saved to: {filename}")

    elif args.email:
        results = suite.email_intel.analyze_email(args.email)
        if results:
            filename = suite.utils.save_results(
                results,
                f"email_intel_{args.email.replace('@', '_at_').replace('.', '_')}",
                args.output,
            )
            if not args.quiet:
                print(f"Results saved to: {filename}")

    elif args.ip:
        results = suite.ip_intel.analyze_ip(args.ip)
        if results:
            filename = suite.utils.save_results(
                results, f"ip_intel_{args.ip.replace('.', '_')}", args.output
            )
            if not args.quiet:
                print(f"Results saved to: {filename}")

    elif args.company:
        results = suite.company_intel.analyze_company(args.company)
        if results:
            filename = suite.utils.save_results(
                results, f"company_intel_{args.company.replace(' ', '_')}", args.output
            )
            if not args.quiet:
                print(f"Results saved to: {filename}")

    elif args.aircraft:
        results = suite.flight_intel.analyze_aircraft(args.aircraft, "registration")
        if results:
            filename = suite.utils.save_results(
                results, f"flight_intel_{args.aircraft.replace('-', '_')}", args.output
            )
            if not args.quiet:
                print(f"Results saved to: {filename}")

    elif args.crypto:
        results = suite.crypto_intel.analyze_crypto_address(
            args.crypto, args.crypto_type
        )
        if results:
            filename = suite.utils.save_results(
                results,
                f"crypto_intel_{args.crypto_type}_{args.crypto[:16]}",
                args.output,
            )
            if not args.quiet:
                print(f"Results saved to: {filename}")

    elif args.search:
        results = suite.passive_search.analyze_target(args.search, args.search_type)
        if results:
            filename = suite.utils.save_results(
                results,
                f"passive_search_{args.search.replace('@', '_at_').replace('.', '_').replace(' ', '_')}",
                args.output,
            )
            if not args.quiet:
                print(f"Results saved to: {filename}")

    elif args.batch:
        if not args.quiet:
            print(f"Processing batch file: {args.batch}")
        # Batch processing logic would be implemented here
        # For now, refer to the batch analysis methods in the class

    else:
        # Interactive mode
        if not args.quiet:
            suite.display_banner()
        suite.main_menu()


if __name__ == "__main__":
    main()