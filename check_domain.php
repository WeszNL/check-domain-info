<?php
/**
 * Domain Information Tool
 *
 * This script offers insights into a domain, covering details such as IP addresses, SSL certificate specifics,
 * mail server configurations, name server records, TXT/DMARC entries, and IP-to-country mapping functionality.
 *
 * @author Wesley van Rossum
 * @copyright (c) 2024 Sernate Webservices
 * @license MIT License
 * @version 1.1.0
 */
?>


<?php
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["domain"])) {
    $domainParam = urlencode($_POST["domain"]);
    header("Location: check_domain.php?domain=" . $domainParam);
    exit;
}
?>

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
            max-width: 400px;
            /* Limit the width of the input box */
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 5px;
        }

        button[type="submit"] {
            background-color: #007BFF;
            color: #fff;
            border: none;
            padding: 12px 18px;
            /* Adjusted padding for a smaller button */
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
    <form method="get">
        <label for="domain">Enter Domain Name (example: domain.com):</label>
        <input type="text" id="domain" name="domain" required
            value="<?php echo isset($_GET['domain']) ? htmlspecialchars($_GET['domain']) : ''; ?>">
        <button type="submit">Lookup</button>
    </form>

    <hr>


    <?php
    //ini_set('display_errors', 1);
//ini_set('display_startup_errors', 1);
//error_reporting(E_ALL);
    $highlightOrg = isset($_GET["highlight"]) ? htmlspecialchars($_GET["highlight"]) : "";
    //$domainPattern = '/^(www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$/';
//$domainPattern = '/^(?:www\.)?[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$/';
    


    require_once "vendor/autoload.php";
    use GeoIp2\Database\Reader;
    use Net_DNS2_Resolver;

    // Create a resolver object
    $resolver = new Net_DNS2_Resolver();

    function getDomainFromUrl($url)
    {
        // Normalize the URL by ensuring it has a scheme (http:// or https://)
        if (!preg_match("~^(?:f|ht)tps?://~i", $url)) {
            $url = "http://" . $url;  // Default to HTTP if no scheme is specified
        }
        $parts = parse_url($url);
        return $parts['host'] ?? false;  // Return the hostname part of the URL
    }

    // Highlight customer
    function highlightText($text, $highlight)
    {
        if ($highlight) {
            return str_ireplace(
                $highlight,
                "<span style='background-color: yellow;'>$highlight</span>",
                $text
            );
        }
        return $text;
    }

    function getCountryInfo($ip)
    {
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

    function getIPv6($domain)
    {
        $dnsRecords = dns_get_record($domain, DNS_AAAA);
        $ipv6Addresses = array_column($dnsRecords, "ipv6");
        return empty($ipv6Addresses) ? null : reset($ipv6Addresses);
    }


    function checkSSLCertificate($domain)
    {
        // Create a stream context that disables peer verification so we can inspect the certificate even if it's expired or mismatched
        $context = stream_context_create([
            "ssl" => [
                "capture_peer_cert" => true,
                "verify_peer" => false,
                "verify_peer_name" => false,
            ],
        ]);

        $socket = @stream_socket_client(
            "ssl://$domain:443",
            $errno,
            $errstr,
            10,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if (!$socket) {
            echo "<p class='expired'>Error: Failed to connect to $domain: $errstr ($errno).</p>";
            return;
        }

        $sslInfo = stream_context_get_params($socket);
        $peerCert = $sslInfo["options"]["ssl"]["peer_certificate"] ?? null;
        fclose($socket);

        if (!$peerCert) {
            echo "<p class='expired'>Error: Could not retrieve the SSL certificate for $domain.</p>";
            return;
        }

        $sslCertificate = openssl_x509_parse($peerCert);
        if (!$sslCertificate) {
            echo "<p class='expired'>Error: Failed to retrieve SSL certificate information for $domain.</p>";
            return;
        }

        // Extract certificate details
        $validFrom = $sslCertificate["validFrom_time_t"];
        $validTo = $sslCertificate["validTo_time_t"];
        date_default_timezone_set('UTC');
        $issuedOn = date("l, F j, Y \a\\t g:i:s A", $validFrom);
        $expiresOn = date("l, F j, Y \a\\t g:i:s A", $validTo);

        $issuerInfo = $sslCertificate['issuer'] ?? [];
        $subjectInfo = $sslCertificate['subject'] ?? [];
        $issuedBy = $issuerInfo['O'] ?? ($issuerInfo['CN'] ?? 'N/A');
        $subjectCN = $subjectInfo['CN'] ?? 'N/A';
        $serialNumber = $sslCertificate['serialNumberHex'] ?? 'N/A';
        $altNames = $sslCertificate["extensions"]["subjectAltName"] ?? "";
        $daysUntilExpiration = ceil(($validTo - time()) / (60 * 60 * 24));
        $fingerprint = openssl_x509_fingerprint($peerCert, 'sha1');

        // Check if the certificate is issued for the domain
        $domainMatches = false;
        if (strcasecmp($subjectCN, $domain) === 0) {
            $domainMatches = true;
        } elseif (!empty($altNames)) {
            $altNamesArray = array_map('trim', explode(',', $altNames));
            foreach ($altNamesArray as $san) {
                // Remove "DNS:" prefix if present
                $sanClean = preg_replace('/^DNS:/i', '', $san);
                if (strcasecmp($sanClean, $domain) === 0) {
                    $domainMatches = true;
                    break;
                }
            }
        }

        if (!$domainMatches) {
            // Determine the displayed certificate domain: use the first SAN if available; otherwise, use CN
            $displayDomain = $subjectCN;
            if (!empty($altNames)) {
                $altNamesArray = array_map('trim', explode(',', $altNames));
                if (!empty($altNamesArray[0])) {
                    $displayDomain = preg_replace('/^DNS:/i', '', $altNamesArray[0]);
                }
            }
            echo "<h2>SSL Certificate Error for $domain:</h2>";
            echo "<ul>";
            echo "<li class='expired'><strong>Error:</strong> Certificate is NOT valid for $domain.</li>";
            echo "<li><strong>Reason:</strong> The certificate is issued for: $displayDomain</li>";
            echo "</ul>";
            return;
        }

        // If the domain matches, output full certificate details
        echo "<h2>SSL Certificate Information for $domain:</h2>";
        echo "<ul>";

        if ($daysUntilExpiration < 0) {
            echo "<li class='expired'><strong>Status:</strong> Certificate expired on $expiresOn</li>";
        } elseif ($daysUntilExpiration <= 14) {
            echo "<li class='expired'><strong>Warning:</strong> Certificate expires in $daysUntilExpiration days (on $expiresOn)</li>";
        } else {
            echo "<li><strong>Status:</strong> Valid ($daysUntilExpiration days remaining, expires on $expiresOn)</li>";
        }
        echo "<li><strong>Issued By:</strong> $issuedBy</li>";
        echo "<li><strong>Common Name (CN):</strong> $subjectCN</li>";
        if (!empty($altNames)) {
            echo "<li><strong>Subject Alternative Names:</strong> $altNames</li>";
        }
        echo "<li><strong>Serial Number:</strong> $serialNumber</li>";
        echo "<li><strong>Fingerprint (SHA1):</strong> $fingerprint</li>";

        if ($issuerInfo === $subjectInfo) {
            echo "<li class='expired'><strong>Note:</strong> The certificate appears to be self-signed.</li>";
        }

        echo "</ul>";
    }


    if ($_SERVER["REQUEST_METHOD"] === "POST" || isset($_GET["domain"])) {
        $urlInput = $_GET["domain"] ?? $_POST["domain"] ?? ''; // Allow both POST and GET requests
        $domain = getDomainFromUrl($urlInput); // Extract the domain name from URL
    
        if (!$domain) {
            echo "<p>Error: Invalid URL or domain name.</p>";
            return;
        }

        // Regex to validate domain (including subdomains)
//   $domainPattern = '/^(?:www\.)?[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$/';
        $domainPattern = '/^([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}$/';
        if (!preg_match($domainPattern, $domain)) {
            echo "<p>Error: please use a valid domain.com or subdomain format.</p>";
        } else {
            echo "<h2>Results for: $domain</h2>";
            // Resolve domain name to IP
            $ipv4 = gethostbyname($domain);
            $ipv6 = getIPv6($domain);

            // Query NS records for the domain
            try {
                $nsResponse = $resolver->query($domain, "NS");
            } catch (Exception $e) {
                $nsResponse = null;
            }

            // Query MX records for the domain
            try {
                $mxResponse = $resolver->query($domain, "MX");
            } catch (Exception $e) {
                $mxResponse = null;
            }

            if ($ipv4 === $domain && $ipv6 === null && (empty($nsResponse) || !is_array($nsResponse->answer)) && (empty($mxResponse) || !is_array($mxResponse->answer))) {
                echo "<p class='expired'>Error: Domain $domain does not exist or is not registered.</p>";
                return;
            }


            $countryInfoIPv4 = getCountryInfo($ipv4);
            $countryNameIPv4 = $countryInfoIPv4["countryName"];
            echo "<p>Resolved IPv4 Address: " .
                highlightText($ipv4, $highlightOrg) .
                " (" . $countryNameIPv4 . ")</p>";

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
                    echo "<p>non-www: " . highlightText($ipv6, $highlightOrg) . "</p>";
                    echo "<p>www: " . highlightText($ipv6WithWww, $highlightOrg) . "</p>";
                } elseif ($ipv6 !== null && $ipv6WithWww !== null && $ipv6 === $ipv6WithWww) {
                    echo "<p>Both www and non-www have the same IPv6 address: " . highlightText($ipv6, $highlightOrg) . "</p>";
                } else {
                    echo "<p>IPv6 address for www variant not available or not matching</p>";
                }
            }

            // Resolve IP to hostname
            $hostnames = gethostbyaddr($ipv4);
            if ($hostnames !== false) {
                $hostname = is_array($hostnames) ? reset($hostnames) : $hostnames;
                echo "<p>Resolved Hostname: " . highlightText($hostname, $highlightOrg) . "</p>";
            } else {
                echo "<p>Resolved Hostname not available</p>";
            }

            // Check SSL certificate validity (consolidated into a single function call)
            checkSSLCertificate($domain);

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
