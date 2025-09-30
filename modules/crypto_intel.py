"""
Cryptocurrency and Blockchain Intelligence Module
Passive analysis of cryptocurrency addresses and transactions
"""

import time
from datetime import datetime

from utils.osint_utils import OSINTUtils


class CryptocurrencyIntelligence(OSINTUtils):
    def __init__(self):
        super().__init__()
        self.results = {}

    def analyze_crypto_address(self, address, currency_type="bitcoin"):
        """Comprehensive cryptocurrency address analysis"""
        self.logger.info(f"Starting crypto analysis for: {address}")

        self.results = {
            "address": address,
            "currency_type": currency_type,
            "timestamp": datetime.now().isoformat(),
            "address_info": self.get_address_info(address, currency_type),
            "transaction_history": self.get_transaction_history(address, currency_type),
            "risk_analysis": self.analyze_risk_factors(address, currency_type),
            "clustering_analysis": self.analyze_address_clustering(
                address, currency_type
            ),
            "exchange_analysis": self.analyze_exchange_connections(
                address, currency_type
            ),
            "darkweb_mentions": self.check_darkweb_mentions(address),
        }

        return self.results

    def get_address_info(self, address, currency_type):
        """Get basic address information"""
        address_info = {}

        try:
            if currency_type.lower() == "bitcoin":
                address_info = self.get_bitcoin_address_info(address)
            elif currency_type.lower() == "ethereum":
                address_info = self.get_ethereum_address_info(address)
            elif currency_type.lower() in ["litecoin", "dogecoin"]:
                address_info = self.get_altcoin_address_info(address, currency_type)
            else:
                address_info = {"error": f"Unsupported currency type: {currency_type}"}

            return address_info

        except Exception as e:
            self.logger.error(f"Address info lookup failed: {e}")
            return {"error": str(e)}

    def get_bitcoin_address_info(self, address):
        """Get Bitcoin address information from public APIs"""
        bitcoin_info = {}

        # Try multiple free Bitcoin APIs
        apis = [
            f"https://blockstream.info/api/address/{address}",
            f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance",
            f"https://chain.api.btc.com/v3/address/{address}",
        ]

        for api_url in apis:
            try:
                response = self.make_request(api_url)
                if response and response.status_code == 200:
                    data = response.json()

                    if "blockstream" in api_url:
                        bitcoin_info["blockstream"] = {
                            "total_received": data.get("chain_stats", {}).get(
                                "funded_txo_sum", 0
                            )
                            / 100000000,
                            "total_sent": data.get("chain_stats", {}).get(
                                "spent_txo_sum", 0
                            )
                            / 100000000,
                            "balance": (
                                data.get("chain_stats", {}).get("funded_txo_sum", 0)
                                - data.get("chain_stats", {}).get("spent_txo_sum", 0)
                            )
                            / 100000000,
                            "transaction_count": data.get("chain_stats", {}).get(
                                "tx_count", 0
                            ),
                        }
                    elif "blockcypher" in api_url:
                        bitcoin_info["blockcypher"] = {
                            "balance": data.get("balance", 0) / 100000000,
                            "total_received": data.get("total_received", 0) / 100000000,
                            "total_sent": data.get("total_sent", 0) / 100000000,
                            "transaction_count": data.get("n_tx", 0),
                        }
                    elif "btc.com" in api_url:
                        if data.get("data"):
                            bitcoin_info["btc_com"] = {
                                "balance": data["data"].get("balance", 0) / 100000000,
                                "received": data["data"].get("received", 0) / 100000000,
                                "sent": data["data"].get("sent", 0) / 100000000,
                                "tx_count": data["data"].get("tx_count", 0),
                            }

                time.sleep(1)  # Rate limiting

            except Exception as e:
                self.logger.error(f"Bitcoin API {api_url} failed: {e}")
                continue

        return bitcoin_info

    def get_ethereum_address_info(self, address):
        """Get Ethereum address information"""
        eth_info = {}

        # Try Etherscan API if available
        etherscan_key = self.get_api_key("ETHERSCAN_API_KEY")

        if etherscan_key:
            try:
                # Get ETH balance
                url = "https://api.etherscan.io/api"
                params = {
                    "module": "account",
                    "action": "balance",
                    "address": address,
                    "tag": "latest",
                    "apikey": etherscan_key,
                }

                response = self.make_request(url, params=params)
                if response:
                    data = response.json()
                    if data.get("status") == "1":
                        balance_wei = int(data.get("result", "0"))
                        balance_eth = (
                            balance_wei / 1000000000000000000
                        )  # Convert Wei to ETH

                        eth_info["etherscan"] = {
                            "balance_eth": balance_eth,
                            "balance_wei": balance_wei,
                        }

                # Get transaction count
                time.sleep(1)
                params["action"] = "txlist"
                params["startblock"] = 0
                params["endblock"] = "latest"
                params["sort"] = "desc"

                response = self.make_request(url, params=params)
                if response:
                    data = response.json()
                    if data.get("status") == "1":
                        transactions = data.get("result", [])
                        eth_info["etherscan"]["transaction_count"] = len(transactions)
                        eth_info["etherscan"]["recent_transactions"] = transactions[:10]

            except Exception as e:
                self.logger.error(f"Etherscan API failed: {e}")

        # Try free Ethereum APIs
        free_apis = [
            f"https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest",
        ]

        for api_url in free_apis:
            try:
                response = self.make_request(api_url)
                if response and response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "1":
                        balance_wei = int(data.get("result", "0"))
                        eth_info["free_api"] = {
                            "balance_eth": balance_wei / 1000000000000000000
                        }
                break

            except Exception as e:
                self.logger.error(f"Free Ethereum API failed: {e}")
                continue

        return eth_info

    def get_altcoin_address_info(self, address, currency_type):
        """Get altcoin address information"""
        altcoin_info = {}

        # Use BlockCypher for supported altcoins
        currency_map = {"litecoin": "ltc", "dogecoin": "doge"}

        if currency_type.lower() in currency_map:
            currency_code = currency_map[currency_type.lower()]

            try:
                url = f"https://api.blockcypher.com/v1/{currency_code}/main/addrs/{address}/balance"
                response = self.make_request(url)

                if response and response.status_code == 200:
                    data = response.json()

                    # Convert satoshis to main currency unit
                    divisor = 100000000  # Standard satoshi divisor

                    altcoin_info["blockcypher"] = {
                        "balance": data.get("balance", 0) / divisor,
                        "total_received": data.get("total_received", 0) / divisor,
                        "total_sent": data.get("total_sent", 0) / divisor,
                        "transaction_count": data.get("n_tx", 0),
                    }

            except Exception as e:
                self.logger.error(f"Altcoin API failed: {e}")

        return altcoin_info

    def get_transaction_history(self, address, currency_type):
        """Get transaction history for address"""
        transaction_history = {}

        try:
            if currency_type.lower() == "bitcoin":
                transaction_history = self.get_bitcoin_transactions(address)
            elif currency_type.lower() == "ethereum":
                transaction_history = self.get_ethereum_transactions(address)
            else:
                transaction_history = {
                    "error": "Transaction history not supported for this currency"
                }

            return transaction_history

        except Exception as e:
            self.logger.error(f"Transaction history lookup failed: {e}")
            return {"error": str(e)}

    def get_bitcoin_transactions(self, address):
        """Get Bitcoin transaction history"""
        try:
            # Use Blockstream API for Bitcoin transactions
            url = f"https://blockstream.info/api/address/{address}/txs"
            response = self.make_request(url)

            if response and response.status_code == 200:
                transactions = response.json()

                processed_txs = []
                for tx in transactions[:20]:  # Limit to 20 recent transactions
                    processed_tx = {
                        "txid": tx.get("txid"),
                        "block_height": tx.get("status", {}).get("block_height"),
                        "block_time": tx.get("status", {}).get("block_time"),
                        "fee": tx.get("fee", 0) / 100000000 if tx.get("fee") else 0,
                        "inputs": len(tx.get("vin", [])),
                        "outputs": len(tx.get("vout", [])),
                        "total_input": sum(
                            [
                                vin.get("prevout", {}).get("value", 0)
                                for vin in tx.get("vin", [])
                            ]
                        )
                        / 100000000,
                        "total_output": sum(
                            [vout.get("value", 0) for vout in tx.get("vout", [])]
                        )
                        / 100000000,
                    }
                    processed_txs.append(processed_tx)

                return {
                    "total_transactions": len(processed_txs),
                    "transactions": processed_txs,
                }

        except Exception as e:
            self.logger.error(f"Bitcoin transactions lookup failed: {e}")
            return {"error": str(e)}

    def get_ethereum_transactions(self, address):
        """Get Ethereum transaction history"""
        etherscan_key = self.get_api_key("ETHERSCAN_API_KEY")

        if not etherscan_key:
            return {"error": "Etherscan API key required for Ethereum transactions"}

        try:
            url = "https://api.etherscan.io/api"
            params = {
                "module": "account",
                "action": "txlist",
                "address": address,
                "startblock": 0,
                "endblock": "latest",
                "page": 1,
                "offset": 20,
                "sort": "desc",
                "apikey": etherscan_key,
            }

            response = self.make_request(url, params=params)
            if response:
                data = response.json()

                if data.get("status") == "1":
                    transactions = data.get("result", [])

                    processed_txs = []
                    for tx in transactions:
                        processed_tx = {
                            "hash": tx.get("hash"),
                            "block_number": tx.get("blockNumber"),
                            "timestamp": tx.get("timeStamp"),
                            "from_address": tx.get("from"),
                            "to_address": tx.get("to"),
                            "value_eth": int(tx.get("value", "0"))
                            / 1000000000000000000,
                            "gas_used": tx.get("gasUsed"),
                            "gas_price": tx.get("gasPrice"),
                        }
                        processed_txs.append(processed_tx)

                    return {
                        "total_transactions": len(processed_txs),
                        "transactions": processed_txs,
                    }

        except Exception as e:
            self.logger.error(f"Ethereum transactions lookup failed: {e}")
            return {"error": str(e)}

    def analyze_risk_factors(self, address, currency_type):
        """Analyze risk factors associated with address"""
        risk_analysis = {"risk_score": 0, "risk_factors": [], "risk_level": "unknown"}

        try:
            # Check address against known blacklists
            blacklist_check = self.check_address_blacklists(address, currency_type)
            if blacklist_check.get("found_in_blacklists"):
                risk_analysis["risk_score"] += 50
                risk_analysis["risk_factors"].append(
                    "Address found in cryptocurrency blacklists"
                )

            # Analyze transaction patterns
            transaction_history = self.get_transaction_history(address, currency_type)
            if "transactions" in transaction_history:
                txs = transaction_history["transactions"]

                # High transaction volume
                if len(txs) > 100:
                    risk_analysis["risk_score"] += 20
                    risk_analysis["risk_factors"].append("High transaction volume")

                # Look for mixing patterns
                mixing_patterns = self.detect_mixing_patterns(txs)
                if mixing_patterns:
                    risk_analysis["risk_score"] += 30
                    risk_analysis["risk_factors"].append(
                        "Possible cryptocurrency mixing detected"
                    )

            # Check for exchange connections
            exchange_analysis = self.analyze_exchange_connections(
                address, currency_type
            )
            if exchange_analysis.get("connected_to_exchanges"):
                # Legitimate exchange connections reduce risk
                risk_analysis["risk_score"] = max(0, risk_analysis["risk_score"] - 10)
                risk_analysis["risk_factors"].append(
                    "Connected to legitimate exchanges (reduces risk)"
                )

            # Determine risk level
            if risk_analysis["risk_score"] >= 70:
                risk_analysis["risk_level"] = "high"
            elif risk_analysis["risk_score"] >= 40:
                risk_analysis["risk_level"] = "medium"
            elif risk_analysis["risk_score"] >= 20:
                risk_analysis["risk_level"] = "low"
            else:
                risk_analysis["risk_level"] = "minimal"

            return risk_analysis

        except Exception as e:
            self.logger.error(f"Risk analysis failed: {e}")
            return {"error": str(e)}

    def check_address_blacklists(self, address, currency_type):
        """Check address against known blacklists"""
        blacklist_results = {
            "found_in_blacklists": False,
            "blacklists_checked": [],
            "matches": [],
        }

        try:
            # Check Bitcoin Abuse Database
            bitcoinabuse_key = self.get_api_key("BITCOINABUSE_API_KEY")

            if bitcoinabuse_key and currency_type.lower() == "bitcoin":
                url = f"https://www.bitcoinabuse.com/api/address/{address}"
                params = {"api_token": bitcoinabuse_key}

                response = self.make_request(url, params=params)
                if response and response.status_code == 200:
                    data = response.json()

                    blacklist_results["blacklists_checked"].append("BitcoinAbuse")

                    if data.get("count", 0) > 0:
                        blacklist_results["found_in_blacklists"] = True
                        blacklist_results["matches"].append(
                            {
                                "source": "BitcoinAbuse",
                                "reports": data.get("count"),
                                "first_seen": data.get("first_seen"),
                                "last_seen": data.get("last_seen"),
                            }
                        )

            # Check other blacklist sources (placeholder)
            # bitcoinwhoswho_key = self.get_api_key('BITCOINWHOSWHO_API_KEY')
            # Additional blacklist checks would go here

            return blacklist_results

        except Exception as e:
            self.logger.error(f"Blacklist check failed: {e}")
            return {"error": str(e)}

    def detect_mixing_patterns(self, transactions):
        """Detect potential cryptocurrency mixing patterns"""
        mixing_indicators = []

        if len(transactions) < 5:
            return mixing_indicators

        try:
            # Look for patterns common in mixing services

            # Pattern 1: Many small inputs, few large outputs
            small_inputs = [tx for tx in transactions if tx.get("inputs", 0) > 10]
            if len(small_inputs) > len(transactions) * 0.3:
                mixing_indicators.append("High number of transactions with many inputs")

            # Pattern 2: Round number outputs (common in mixing)
            round_outputs = []
            for tx in transactions:
                total_output = tx.get("total_output", 0)
                if total_output and (
                    total_output == int(total_output)
                    or total_output in [0.1, 0.5, 1.0, 5.0, 10.0]
                ):
                    round_outputs.append(tx)

            if len(round_outputs) > len(transactions) * 0.4:
                mixing_indicators.append("High frequency of round number outputs")

            # Pattern 3: Consistent time intervals (automated mixing)
            timestamps = [
                tx.get("block_time", 0) for tx in transactions if tx.get("block_time")
            ]
            if len(timestamps) > 5:
                intervals = [
                    timestamps[i] - timestamps[i + 1]
                    for i in range(len(timestamps) - 1)
                ]
                avg_interval = sum(intervals) / len(intervals) if intervals else 0

                # Check if intervals are suspiciously regular
                regular_intervals = [
                    i for i in intervals if abs(i - avg_interval) < avg_interval * 0.1
                ]
                if len(regular_intervals) > len(intervals) * 0.6:
                    mixing_indicators.append("Regular transaction timing patterns")

            return mixing_indicators

        except Exception as e:
            self.logger.error(f"Mixing pattern detection failed: {e}")
            return []

    def analyze_address_clustering(self, address, currency_type):
        """Analyze address clustering and relationships"""
        try:
            clustering_analysis = {
                "related_addresses": [],
                "clustering_confidence": "unknown",
            }

            # Get transaction history to analyze input/output relationships
            transaction_history = self.get_transaction_history(address, currency_type)

            if "transactions" in transaction_history:
                transactions = transaction_history["transactions"]
                related_addresses = set()

                # Find addresses that frequently interact with target address
                for tx in transactions:
                    if currency_type.lower() == "bitcoin":
                        # For Bitcoin, we need to look at inputs/outputs more carefully
                        # This is a simplified analysis
                        if tx.get("inputs", 0) > 1:
                            related_addresses.add("multi_input_transaction")
                    elif currency_type.lower() == "ethereum":
                        from_addr = tx.get("from_address")
                        to_addr = tx.get("to_address")

                        if from_addr and from_addr != address:
                            related_addresses.add(from_addr)
                        if to_addr and to_addr != address:
                            related_addresses.add(to_addr)

                clustering_analysis["related_addresses"] = list(related_addresses)[
                    :20
                ]  # Limit results
                clustering_analysis["clustering_confidence"] = "basic_analysis"

            return clustering_analysis

        except Exception as e:
            self.logger.error(f"Address clustering analysis failed: {e}")
            return {"error": str(e)}

    def analyze_exchange_connections(self, address, currency_type):
        """Analyze connections to cryptocurrency exchanges"""
        try:
            exchange_analysis = {
                "connected_to_exchanges": False,
                "exchange_connections": [],
                "analysis_method": "basic_pattern_matching",
            }

            # Known exchange address patterns (simplified)
            known_exchange_patterns = {
                "binance": ["bc1q", "1binance"],  # Example patterns
                "coinbase": ["1coinbase", "3coinbase"],
                "kraken": ["1kraken"],
                "bitfinex": ["1bitfinex", "3bitfinex"],
            }

            # Analyze transaction history for exchange patterns
            transaction_history = self.get_transaction_history(address, currency_type)

            if "transactions" in transaction_history:
                transactions = transaction_history["transactions"]

                for tx in transactions:
                    if currency_type.lower() == "ethereum":
                        from_addr = tx.get("from_address", "").lower()
                        to_addr = tx.get("to_address", "").lower()

                        for exchange, patterns in known_exchange_patterns.items():
                            for pattern in patterns:
                                if pattern in from_addr or pattern in to_addr:
                                    exchange_analysis["connected_to_exchanges"] = True
                                    exchange_analysis["exchange_connections"].append(
                                        {
                                            "exchange": exchange,
                                            "transaction_hash": tx.get("hash"),
                                            "direction": "received"
                                            if pattern in from_addr
                                            else "sent",
                                        }
                                    )

            return exchange_analysis

        except Exception as e:
            self.logger.error(f"Exchange connection analysis failed: {e}")
            return {"error": str(e)}

    def check_darkweb_mentions(self, address):
        """Check for mentions of address on darkweb/forums"""
        try:
            # Use Intel X API if available
            intelx_key = self.get_api_key("INTELX_API_KEY")

            if intelx_key:
                url = "https://2.intelx.io/phonebook/search"
                headers = {"x-key": intelx_key}
                data = {"term": address, "maxresults": 10, "media": 0, "sort": 4}

                response = self.utils.tor_post(
                    url, headers=headers, json=data, timeout=30
                )
                if response.status_code == 200:
                    results = response.json()

                    return {
                        "found_mentions": len(results.get("records", [])) > 0,
                        "total_mentions": len(results.get("records", [])),
                        "sources": [
                            record.get("bucket")
                            for record in results.get("records", [])
                        ][:5],
                    }

            return {"checked": False, "reason": "No Intel X API key available"}

        except Exception as e:
            self.logger.error(f"Darkweb mentions check failed: {e}")
            return {"error": str(e)}

    def generate_report(self):
        """Generate cryptocurrency intelligence report"""
        if not self.results:
            return "No analysis results available"

        report = f"""
# Cryptocurrency Intelligence Report: {self.results['address']}
Currency: {self.results['currency_type'].title()}
Generated: {self.results['timestamp']}

## Address Information
"""

        # Add address info
        address_info = self.results.get("address_info", {})
        for source, data in address_info.items():
            if isinstance(data, dict) and "balance" in data:
                report += f"\n### {source.title()} Data:\n"
                report += f"Balance: {data.get('balance', 0):.8f} {self.results['currency_type'].upper()}\n"
                report += f"Total Received: {data.get('total_received', 0):.8f}\n"
                report += f"Total Sent: {data.get('total_sent', 0):.8f}\n"
                report += f"Transaction Count: {data.get('transaction_count', 0)}\n"

        # Add risk analysis
        risk_analysis = self.results.get("risk_analysis", {})
        risk_score = risk_analysis.get("risk_score", 0)
        risk_level = risk_analysis.get("risk_level", "unknown")

        report += "\n## Risk Assessment\n"
        report += f"Risk Score: {risk_score}/100\n"
        report += f"Risk Level: {risk_level.upper()}\n"

        risk_factors = risk_analysis.get("risk_factors", [])
        if risk_factors:
            report += "\n### Risk Factors:\n"
            for factor in risk_factors:
                report += f"⚠️  {factor}\n"
        else:
            report += "✅ No significant risk factors identified\n"

        # Add transaction summary
        transaction_history = self.results.get("transaction_history", {})
        total_txs = transaction_history.get("total_transactions", 0)

        report += "\n## Transaction Activity\n"
        report += f"Total Transactions: {total_txs}\n"

        if total_txs > 0:
            recent_txs = transaction_history.get("transactions", [])[:5]
            report += "\n### Recent Transactions:\n"
            for tx in recent_txs:
                tx_id = tx.get("txid") or tx.get("hash", "N/A")
                report += f"- Transaction: {tx_id[:16]}...\n"

        return report
