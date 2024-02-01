<!DOCTYPE html>
<html>
<head>
    <title>Domain Information Tool</title>
    <style>
        body {
            font-family: Arial, sans-serif;
        }
        h1 {
            color: #333;
        }
        form {
            margin-bottom: 20px;
        }
        label {
            font-weight: bold;
            display: block;
            margin-bottom: 5px;
        }
        input[type="text"] {
            width: 100%;
            max-width: 400px; /* Limit the width of the input box */
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 5px;
        }
        button[type="submit"] {
            background-color: #007BFF;
            color: #fff;
            border: none;
            padding: 12px 18px; /* Adjusted padding for a smaller button */
            border-radius: 5px;
            cursor: pointer;
        }
        hr {
            margin-top: 20px;
        }
        ul {
            list-style-type: none;
            padding: 0;
        }
        ul li {
            margin-bottom: 5px;
        }
        strong {
            color: #007BFF;
        }
        .expired {
        color: red;
        font-weight: bold;
        }
    </style>
</head>
<body>
    <h1>Domain Information Tool</h1>
    <form method="post">
        <label for="domain">Enter Domain Name (example: domain.com):</label>
        <input type="text" id="domain" name="domain" required>
        <button type="submit">Lookup</button>
    </form>
    <hr>


<?php
//error_reporting(E_ALL);
//ini_set("display_errors", 1);
$highlightOrg = isset($_GET["highlight"]) ? $_GET["highlight"] : "";
//$domainPattern = '/^(www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$/';
$domainPattern = '/^(?:www\.)?[a-zA-Z0-9-]+(?:\.[a-zA-Z]{2,})+$/';

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once "vendor/autoload.php";
use GeoIp2\Database\Reader;
use Net_DNS2_Resolver;

// Create a resolver object
$resolver = new Net_DNS2_Resolver();

// Highlight customer
function highlightText($text, $highlight) {
	if ($highlight) {
		return str_ireplace(
			$highlight,
			"<span style='background-color: yellow;'>$highlight</span>",
			$text
		);
	}
	return $text;
}

function getCountryInfo($ip) {
	$reader = new Reader("/usr/share/GeoIP/GeoLite2-City.mmdb"); // Use correct path
	try {
		$record = $reader->city($ip);
		$countryName = $record->country->name;
		$countryCode = $record->country->isoCode;
		$cityName = $record->city->name;

		return [
			"countryName" => $countryName,
			"countryCode" => $countryCode,
			"cityName" => $cityName,
		];
	} catch (Exception $e) {
		return [
			"countryName" => "Country information not available",
			"countryCode" => "N/A",
			"cityName" => "City information not available",
		];
	}
}

function getIPv6($domain) {
	$dnsRecords = dns_get_record($domain, DNS_AAAA);
	$ipv6Addresses = array_column($dnsRecords, "ipv6");
	return empty($ipv6Addresses) ? null : reset($ipv6Addresses);
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
	$domain = $_POST["domain"];
	$domain = preg_replace("/^www\./", "", $domain); // Remove leading "www" if present

	// Check if the domain is a subdomain
	if (!preg_match($domainPattern, $domain)) {
		echo "<p>Error: please use domain.com and no subdomain</p>";
	} else {
		echo "<h2>Results for: $domain</h2>";
		// Resolve domain name to IP
		$ipv4 = gethostbyname($domain);
		$ipv6 = getIPv6($domain);

		$countryInfoIPv4 = getCountryInfo($ipv4);
		$countryNameIPv4 = $countryInfoIPv4["countryName"];
		echo "<p>Resolved IPv4 Address: " .
		highlightText($ipv4, $highlightOrg) .
			" (" .
			$countryNameIPv4 .
			")</p>";

		// Check if it's a subdomain before checking www records and matching IPv6
		if (substr_count($domain, '.') === 1) {
			// Resolve IPv6 for www variant if not a subdomain
			$ipv6WithWww = getIPv6("www.$domain");

			if ($ipv6WithWww !== null) {
				echo "<p>IPv6 address for www variant: " .
				highlightText($ipv6WithWww, $highlightOrg) .
					"</p>";
			} else {
				echo "<p>IPv6 address for www variant not available</p>";
			}

			// Check if www and non-www have different IPv6 addresses
			if ($ipv6 !== null && $ipv6WithWww !== null && $ipv6 !== $ipv6WithWww) {
				echo "<p>www and non-www have different IPv6 addresses:</p>";
				echo "<p>non-www: " .
				highlightText($ipv6, $highlightOrg) .
					"</p>";
				echo "<p>www: " .
				highlightText($ipv6WithWww, $highlightOrg) .
					"</p>";
			} elseif ($ipv6 !== null && $ipv6WithWww !== null && $ipv6 === $ipv6WithWww) {
				echo "<p>Both www and non-www have the same IPv6 address: " .
				highlightText($ipv6, $highlightOrg) .
					"</p>";
			} else {
				echo "<p>IPv6 address for www variant not available or not matching</p>";
			}
		}

		// Resolve IP to hostname
		$hostnames = gethostbyaddr($ipv4);
		if ($hostnames !== false) {
			$hostname = is_array($hostnames) ? reset($hostnames) : $hostnames;
			echo "<p>Resolved Hostname: " .
			highlightText($hostname, $highlightOrg) .
				"</p>";
		} else {
			echo "<p>Resolved Hostname not available</p>";
		}

// Check SSL certificate validity
		$context = stream_context_create([
			"ssl" => ["capture_peer_cert" => true],
		]);
		$socket = stream_socket_client(
			"ssl://$domain:443",
			$errno,
			$errstr,
			30,
			STREAM_CLIENT_CONNECT,
			$context
		);

		if (!$socket) {
			echo "<p class='expired'>Error: Failed to connect to $domain: $errstr ($errno).</p>";
		} else {
			$sslInfo = stream_context_get_params($socket);
			$sslCertificate = openssl_x509_parse(
				$sslInfo["options"]["ssl"]["peer_certificate"]
			);

			if (!$sslCertificate) {
				echo "<p class='expired'>Error: Failed to retrieve SSL certificate information for $domain.</p>";
			} else {
				$validFrom = $sslCertificate["validFrom_time_t"];
				$validTo = $sslCertificate["validTo_time_t"];

				// Explicitly set the time zone
				date_default_timezone_set('UTC');

				// Format dates in a human-readable format
				$issuedOn = date("l, F j, Y \a\\t g:i:s A", $validFrom);
				$expiresOn = date("l, F j, Y \a\\t g:i:s A", $validTo);

				// Extract the Issuer information from the SSL certificate
				$issuerInfo = isset($sslCertificate['issuer']) ? $sslCertificate['issuer'] : [];
				$issuedBy = isset($issuerInfo['O']) ? $issuerInfo['O'] : (isset($issuerInfo['CN']) ? $issuerInfo['CN'] : 'N/A');

				$daysUntilExpiration = ceil(
					($validTo - time()) / (60 * 60 * 24)
				);

				echo "<h2>SSL Certificate Information for $domain:</h2>";
				echo "<ul>";

				if ($daysUntilExpiration <= 14) {
					echo "<li class='expired'><strong>Days Until Expiration:</strong> $daysUntilExpiration days</li>";
				} else {
					echo "<li><strong>Days Until Expiration:</strong> $daysUntilExpiration days</li>";
				}

				echo "<li><strong>Issued By:</strong> $issuedBy</li>";
				echo "<li><strong>Valid From:</strong> $issuedOn</li>";
				echo "<li><strong>Valid Until:</strong> $expiresOn</li>";

				echo "</ul>";
			}

			fclose($socket);
		}

// Query MX records for the domain using Net_DNS2
		$mxResponse = $resolver->query($domain, "MX");

		echo "<h2>Mail Servers (MX) for $domain:</h2>";
		echo "<ul>";

// Check if MX records are present and contain valid mail servers
		if ($mxResponse && !empty($mxResponse->answer) && is_array($mxResponse->answer)) {
			foreach ($mxResponse->answer as $mx) {
				// Check if the MX record has valid mail server information
				if (isset($mx->exchange) && isset($mx->preference)) {
					$exchange = highlightText($mx->exchange, $highlightOrg);
					$preference = highlightText($mx->preference, $highlightOrg);
					echo "<li><strong>Mail Exchanger:</strong> $exchange (Priority: $preference)</li>";
				}
			}
			echo "</ul>";
		} else {
			// If MX records are not available or do not contain valid mail servers, display a notice
			echo "<p>No valid mail server information available for $domain.</p>";
		}

// Query NS records for the subdomain using Net_DNS2
		$subdomainNSResponse = $resolver->query($domain, "NS");
		if ($subdomainNSResponse) {
			// Check if NS records are present in the authority section
			$authorityRecords = $subdomainNSResponse->authority;

			// Check if authority records are present and include NS records
			$nsAuthorityRecords = array_filter($authorityRecords, function ($record) {
				return $record->type === 'NS';
			});

			if (!empty($nsAuthorityRecords)) {
				echo "<h2>Name Servers (NS) for $domain:</h2>";
				echo "<ul>";
				foreach ($nsAuthorityRecords as $authorityRecord) {
					$nsdname = isset($authorityRecord->nsdname) ? $authorityRecord->nsdname : 'N/A';
					$nsdname = highlightText($nsdname, $highlightOrg);
					echo "<li><strong>Name Server:</strong> $nsdname</li>";
				}
				echo "</ul>";
			} else {
				// If NS records for subdomain are not available, use the parent domain's NS records
				$parentDomain = implode('.', array_slice(explode('.', $domain), -2));
				$parentNSResponse = $resolver->query($parentDomain, "NS");

				if ($parentNSResponse) {
					echo "<h2>Name Servers (NS) for $domain (using parent domain $parentDomain):</h2>";
					echo "<ul>";
					foreach ($parentNSResponse->answer as $ns) {
						$nsdname = isset($ns->nsdname) ? $ns->nsdname : 'N/A';
						$nsdname = highlightText($nsdname, $highlightOrg);
						echo "<li><strong>Name Server:</strong> $nsdname</li>";
					}
					echo "</ul>";
				} else {
					echo "<p>Name server information not available.</p>";
				}
			}
		} else {
			// If NS records for subdomain are not available, use the parent domain's NS records
			$parentDomain = implode('.', array_slice(explode('.', $domain), -2));
			$parentNSResponse = $resolver->query($parentDomain, "NS");
			if ($parentNSResponse) {
				echo "<h2>Name Servers (NS) for $domain (using parent domain $parentDomain):</h2>";
				echo "<ul>";
				foreach ($parentNSResponse->answer as $ns) {
					$nsdname = isset($ns->nsdname) ? $ns->nsdname : 'N/A';
					$nsdname = highlightText($nsdname, $highlightOrg);
					echo "<li><strong>Name Server:</strong> $nsdname</li>";
				}
				echo "</ul>";
			} else {
				echo "<p>Name server information not available.</p>";
			}
		}

		// Query SPF records for the domain using dns_get_record
		$txtRecords = dns_get_record($domain, DNS_TXT);
		if ($txtRecords) {
			echo "<h2>TXT Records (SPF) for $domain:</h2>";
			echo "<ul>";
			foreach ($txtRecords as $record) {
				if (
					isset($record["txt"]) &&
					strpos($record["txt"], "v=spf1") === 0
				) {
					$txt = highlightText($record["txt"], $highlightOrg);
					echo "<li><strong>TXT Record (SPF):</strong> $txt</li>";
				}
			}
			echo "</ul>";
		} else {
			echo "<p>SPF (TXT) record information not available/set.</p>";
		}
		$dmarcRecords = dns_get_record("_dmarc." . $domain, DNS_TXT);
		if ($dmarcRecords) {
			echo "<h2>DMARC Record for $domain:</h2>";
			echo "<ul>";
			foreach ($dmarcRecords as $record) {
				if (
					isset($record["txt"]) &&
					strpos($record["txt"], "v=DMARC1") === 0
				) {
					$dmarcTxt = highlightText($record["txt"], $highlightOrg);
					echo "<li><strong>DMARC Record:</strong> $dmarcTxt</li>";
				}
			}
			echo "</ul>";
		} else {
			echo "<p>DMARC record information not available/set.</p>";
		}
	}
}
?>

</body>
</html>
