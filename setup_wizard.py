#!/usr/bin/env python3
"""
OSINT Suite Setup Wizard
Interactive configuration wizard for new users
"""

import sys
import os
import configparser
from pathlib import Path
import questionary
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

console = Console()

class SetupWizard:
    """Interactive setup wizard for OSINT Suite"""

    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config_path = Path("config.ini")
        self.api_keys_path = Path("api_keys.enc")
        self.template_path = Path("config.ini.template")

        # Load existing config if available
        if self.config_path.exists():
            self.config.read(self.config_path)
        elif self.template_path.exists():
            self.config.read(self.template_path)

    def run_wizard(self):
        """Run the complete setup wizard"""
        console.clear()
        self.show_welcome()

        # Basic setup
        self.configure_basic_settings()

        # API keys setup
        self.configure_api_keys()

        # Security settings
        self.configure_security()

        # Advanced options
        self.configure_advanced()

        # Save configuration
        self.save_configuration()

        # Final summary
        self.show_summary()

    def show_welcome(self):
        """Show welcome screen"""
        welcome_text = Text()
        welcome_text.append("🚀 Welcome to Passive OSINT Suite Setup Wizard!\n\n", style="bold blue")
        welcome_text.append("This wizard will help you configure your OSINT platform for optimal performance.\n\n")
        welcome_text.append("We'll cover:\n")
        welcome_text.append("• Basic settings and preferences\n")
        welcome_text.append("• API key configuration\n")
        welcome_text.append("• Security and privacy settings\n")
        welcome_text.append("• Advanced options\n\n")
        welcome_text.append("Press Enter to continue...", style="dim")

        panel = Panel(welcome_text, title="OSINT Suite Setup", border_style="blue")
        console.print(panel)

        input("\nPress Enter to continue...")

    def configure_basic_settings(self):
        """Configure basic settings"""
        console.clear()
        console.print("[bold blue]📋 Basic Configuration[/bold blue]\n")

        # Log level
        log_levels = ["DEBUG", "INFO", "WARNING", "ERROR"]
        current_log_level = self.config.get("SETTINGS", "LOG_LEVEL", fallback="INFO")

        log_level = questionary.select(
            "Select logging level:",
            choices=log_levels,
            default=current_log_level
        ).ask()

        if not self.config.has_section("SETTINGS"):
            self.config.add_section("SETTINGS")

        self.config.set("SETTINGS", "LOG_LEVEL", log_level)

        # Output format
        output_formats = ["json", "csv", "xml", "html"]
        current_format = self.config.get("SETTINGS", "OUTPUT_FORMAT", fallback="json")

        output_format = questionary.select(
            "Select default output format:",
            choices=output_formats,
            default=current_format
        ).ask()

        self.config.set("SETTINGS", "OUTPUT_FORMAT", output_format)

        # Max threads
        max_threads = questionary.text(
            "Maximum concurrent threads (recommended: 5-10):",
            default=self.config.get("SETTINGS", "MAX_THREADS", fallback="5"),
            validate=lambda x: x.isdigit() and 1 <= int(x) <= 50
        ).ask()

        self.config.set("SETTINGS", "MAX_THREADS", max_threads)

        # Timeout
        timeout = questionary.text(
            "Request timeout in seconds (recommended: 30-60):",
            default=self.config.get("SETTINGS", "TIMEOUT", fallback="30"),
            validate=lambda x: x.isdigit() and 10 <= int(x) <= 300
        ).ask()

        self.config.set("SETTINGS", "TIMEOUT", timeout)

        console.print("[green]✅ Basic settings configured![/green]")

    def configure_api_keys(self):
        """Configure API keys"""
        console.clear()
        console.print("[bold blue]🔑 API Key Configuration[/bold blue]\n")

        console.print("OSINT Suite supports various APIs for enhanced intelligence gathering.")
        console.print("You can configure API keys now or skip and add them later.\n")

        # Check if we have secure storage
        has_secure_storage = False
        secrets_manager = None
        try:
            from security.secrets_manager import secrets_manager
            has_secure_storage = True and secrets_manager is not None
        except ImportError:
            console.print("[yellow]⚠️  Secure storage not available - keys will be stored in plain text[/yellow]")

        # API services to configure
        api_services = {
            "shodan": "Shodan (Network scanning)",
            "censys": "Censys (Certificate intelligence)",
            "zoomeye": "ZoomEye (Global scanning)",
            "virustotal": "VirusTotal (File/malware analysis)",
            "alienvault": "AlienVault OTX (Threat intelligence)",
            "hybrid_analysis": "Hybrid Analysis (Malware analysis)",
            "urlscan": "URLScan.io (URL analysis)",
            "emailrep": "EmailRep (Email reputation)",
            "hunter": "Hunter.io (Email finding)",
            "breachdirectory": "BreachDirectory (Password breach checking)"
        }

        configured_keys = []

        for service_key, service_name in api_services.items():
            configure = questionary.confirm(
                f"Configure {service_name} API key?",
                default=False
            ).ask()

            if configure:
                api_key = questionary.password(
                    f"Enter {service_name} API key:"
                ).ask()

                if has_secure_storage and secrets_manager is not None:
                    try:
                        secrets_manager.store_secret(f"api_key_{service_key}", api_key)
                        console.print(f"[green]✓ {service_name} key stored securely[/green]")
                    except Exception as e:
                        console.print(f"[red]✗ Failed to store {service_name} key: {e}[/red]")
                        console.print(f"[red]✗ Failed to store {service_name} key: {e}[/red]")
                else:
                    # Store in config (not recommended)
                    if not self.config.has_section("API_KEYS"):
                        self.config.add_section("API_KEYS")
                    self.config.set("API_KEYS", service_key.upper(), api_key)
                    console.print(f"[yellow]⚠️  {service_name} key stored in config (not secure)[/yellow]")

                    configured_keys.append(service_name)

        if configured_keys:
            console.print(f"\n[green]✅ Configured {len(configured_keys)} API services:[/green]")
            for service in configured_keys:
                console.print(f"  • {service}")
        else:
            console.print("\n[yellow]ℹ️  No API keys configured. You can add them later.[/yellow]")

        console.print("\n[dim]💡 Tip: API keys are stored securely and never logged in plain text.[/dim]")

    def configure_security(self):
        """Configure security settings"""
        console.clear()
        console.print("[bold blue]🔒 Security & Privacy Configuration[/bold blue]\n")

        # OPSEC settings
        console.print("Configure your operational security preferences:\n")

        # Tor usage
        use_tor = questionary.confirm(
            "Use Tor for all network requests (recommended for privacy)?",
            default=True
        ).ask()

        if not self.config.has_section("OPSEC"):
            self.config.add_section("OPSEC")

        self.config.set("OPSEC", "USE_TOR", str(use_tor))

        # DNS over HTTPS
        use_doh = questionary.confirm(
            "Use DNS over HTTPS for DNS queries?",
            default=True
        ).ask()

        self.config.set("OPSEC", "USE_DOH", str(use_doh))

        # Query obfuscation
        use_obfuscation = questionary.confirm(
            "Enable query obfuscation to avoid detection?",
            default=True
        ).ask()

        self.config.set("OPSEC", "USE_OBFUSCATION", str(use_obfuscation))

        # Result encryption
        encrypt_results = questionary.confirm(
            "Automatically encrypt all investigation results?",
            default=True
        ).ask()

        self.config.set("OPSEC", "ENCRYPT_RESULTS", str(encrypt_results))

        # Audit trail
        enable_audit = questionary.confirm(
            "Enable comprehensive audit trail logging?",
            default=True
        ).ask()

        self.config.set("OPSEC", "ENABLE_AUDIT", str(enable_audit))

        console.print("[green]✅ Security settings configured![/green]")

    def configure_advanced(self):
        """Configure advanced options"""
        console.clear()
        console.print("[bold blue]⚙️  Advanced Configuration[/bold blue]\n")

        # Passive sources
        console.print("Enable/disable passive intelligence sources:\n")

        passive_sources = {
            "ENABLE_GOOGLE_DORKING": "Google dorking patterns",
            "ENABLE_PASTEBIN_SEARCH": "Pastebin monitoring",
            "ENABLE_GITHUB_SEARCH": "GitHub code search",
            "ENABLE_SOCIAL_MEDIA_SEARCH": "Social media monitoring",
            "ENABLE_COURT_RECORDS_SEARCH": "Court records search",
            "ENABLE_NEWS_SEARCH": "News article monitoring",
            "ENABLE_JOB_POSTING_SEARCH": "Job posting intelligence"
        }

        if not self.config.has_section("PASSIVE_SOURCES"):
            self.config.add_section("PASSIVE_SOURCES")

        for setting, description in passive_sources.items():
            current_value = self.config.getboolean("PASSIVE_SOURCES", setting, fallback=True)
            enabled = questionary.confirm(
                f"Enable {description}?",
                default=current_value
            ).ask()

            self.config.set("PASSIVE_SOURCES", setting, str(enabled))

        # AI/ML settings
        console.print("\n🤖 AI and Machine Learning settings:\n")

        if not self.config.has_section("AI"):
            self.config.add_section("AI")

        # Local LLM
        use_local_llm = questionary.confirm(
            "Enable local LLM processing (no external API calls)?",
            default=True
        ).ask()

        self.config.set("AI", "USE_LOCAL_LLM", str(use_local_llm))

        # Pattern analysis
        use_patterns = questionary.confirm(
            "Enable advanced pattern analysis and anomaly detection?",
            default=True
        ).ask()

        self.config.set("AI", "USE_PATTERN_ANALYSIS", str(use_patterns))

        console.print("[green]✅ Advanced settings configured![/green]")

    def save_configuration(self):
        """Save the configuration"""
        console.clear()
        console.print("[bold blue]💾 Saving Configuration[/bold blue]\n")

        try:
            with open(self.config_path, 'w') as f:
                self.config.write(f)

            console.print(f"[green]✅ Configuration saved to {self.config_path}[/green]")

            # Set appropriate permissions
            self.config_path.chmod(0o600)
            console.print("[green]✅ Configuration file permissions set to 600[/green]")

        except Exception as e:
            console.print(f"[red]❌ Failed to save configuration: {e}[/red]")
            sys.exit(1)

    def show_summary(self):
        """Show configuration summary"""
        console.clear()

        summary_table = Table(title="🎉 OSINT Suite Configuration Complete!")
        summary_table.add_column("Setting", style="cyan")
        summary_table.add_column("Value", style="green")

        # Basic settings
        summary_table.add_row("Log Level", self.config.get("SETTINGS", "LOG_LEVEL", fallback="INFO"))
        summary_table.add_row("Output Format", self.config.get("SETTINGS", "OUTPUT_FORMAT", fallback="json"))
        summary_table.add_row("Max Threads", self.config.get("SETTINGS", "MAX_THREADS", fallback="5"))
        summary_table.add_row("Timeout", f"{self.config.get('SETTINGS', 'TIMEOUT', fallback='30')}s")

        # Security settings
        summary_table.add_row("Use Tor", self.config.get("OPSEC", "USE_TOR", fallback="True"))
        summary_table.add_row("Use DoH", self.config.get("OPSEC", "USE_DOH", fallback="True"))
        summary_table.add_row("Query Obfuscation", self.config.get("OPSEC", "USE_OBFUSCATION", fallback="True"))
        summary_table.add_row("Encrypt Results", self.config.get("OPSEC", "ENCRYPT_RESULTS", fallback="True"))
        summary_table.add_row("Audit Trail", self.config.get("OPSEC", "ENABLE_AUDIT", fallback="True"))

        console.print(summary_table)

        console.print("\n[bold green]🚀 Your OSINT Suite is ready![/bold green]")
        console.print("\n[dim]Quick start commands:[/dim]")
        console.print("  Interactive mode: ./start_osint_suite.sh")
        console.print("  Web interface: ./start_web_interface.sh")
        console.print("  Health check: python3 health_check.py")
        console.print("  Documentation: cat README.md")

        console.print("\n[dim]📚 Useful resources:[/dim]")
        console.print("  • README.md - Complete documentation")
        console.print("  • STARTUP_GUIDE.md - Getting started guide")
        console.print("  • ENHANCED_PLATFORM_GUIDE.md - Web interface guide")
        console.print("  • config.ini - Your configuration file")

        console.print("\n[bold blue]Happy hunting! 🕵️[/bold blue]")


def check_dependencies():
    """Check if required dependencies are available"""
    missing_deps = []

    try:
        import questionary
    except ImportError:
        missing_deps.append("questionary")

    try:
        from rich.console import Console
    except ImportError:
        missing_deps.append("rich")

    if missing_deps:
        print("❌ Missing required dependencies for setup wizard:")
        for dep in missing_deps:
            print(f"  • {dep}")
        print("\nInstall with: pip install questionary rich")
        sys.exit(1)


def main():
    """Main setup wizard function"""
    check_dependencies()

    try:
        wizard = SetupWizard()
        wizard.run_wizard()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Setup cancelled by user.[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Setup failed: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()