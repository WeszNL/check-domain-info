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
error_reporting(E_ALL);
ini_set('display_errors', 1);
$highlightOrg = isset($_GET['highlight']) ? $_GET['highlight'] : "";
$domainPattern = '/^(www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$/';


//ini_set('display_errors', 1);
//ini_set('display_startup_errors', 1);
//error_reporting(E_ALL);

require_once 'vendor/autoload.php';
use GeoIp2\Database\Reader;


// Highlight customer
function highlightText($text, $highlight) {
    if ($highlight) {
        return str_ireplace($highlight, "<span style='background-color: yellow;'>$highlight</span>", $text);
    }
    return $text;
}


function getCountryInfo($ip) {
    $reader = new Reader('/usr/share/GeoIP/GeoLite2-City.mmdb'); // Use correct path
    try {
        $record = $reader->city($ip);
        $countryName = $record->country->name;
        $countryCode = $record->country->isoCode;
        $cityName = $record->city->name;

        return [
            'countryName' => $countryName,
            'countryCode' => $countryCode,
            'cityName' => $cityName
        ];
    } catch (Exception $e) {
        return [
            'countryName' => 'Country information not available',
            'countryCode' => 'N/A',
            'cityName' => 'City information not available'
        ];
    }
}


function getIPv6($domain) {
    $dnsRecords = dns_get_record($domain, DNS_AAAA);
    $ipv6Addresses = array_column($dnsRecords, 'ipv6');
    return empty($ipv6Addresses) ? null : reset($ipv6Addresses);
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $domain = $_POST["domain"];
    $domain = preg_replace('/^www\./', '', $domain); // Remove leading "www" if present


    // Check if the domain is a subdomain
    if (!preg_match($domainPattern, $domain)) {
//    if (substr_count($domain, '.') < 1 || substr_count($domain, '.') > 2) {
        echo "<p>Error: please use domain.com and no subdomain</p>";
    } else {
        echo "<h2>Results for: $domain</h2>"; 
       // Resolve domain name to IP
        $ipv4 = gethostbyname($domain);
        $ipv6 = getIPv6($domain);

        $countryInfoIPv4 = getCountryInfo($ipv4);
        $countryNameIPv4 = $countryInfoIPv4['countryName'];
        echo "<p>Resolved IPv4 Address: " . highlightText($ipv4, $highlightOrg) . " (" . $countryNameIPv4 . ")</p>";

     if ($ipv6) {
    $countryInfoIPv6 = getCountryInfo($ipv6);
    $countryNameIPv6 = $countryInfoIPv6['countryName'];
    echo "<p>Resolved IPv6 Address: " . highlightText($ipv6, $highlightOrg) . " (" . $countryNameIPv6 . ")</p>";

    $ipv6WithoutWww = getIPv6($domain);
    $ipv6WithWww = getIPv6("www.$domain");

    if ($ipv6WithoutWww !== null && $ipv6WithWww !== null && $ipv6WithoutWww !== $ipv6WithWww) {
        echo "<p>www and non-www have different IPv6 addresses:</p>";
        echo "<p>non-www: " . highlightText($ipv6WithoutWww, $highlightOrg) . "</p>";
        echo "<p>www: " . highlightText($ipv6WithWww, $highlightOrg) . "</p>";
    } elseif ($ipv6WithoutWww !== null && $ipv6WithWww !== null && $ipv6WithoutWww === $ipv6WithWww) {
        echo "<p>Both www and non-www have the same IPv6 address: " . highlightText($ipv6WithoutWww, $highlightOrg) . "</p>";
    } else {
        echo "<p>IPv6 address for www variant not available or not matching</p>";
    }
} else {
    echo "<p>IPv6 address not available</p>";
}

      

        // Resolve IP to hostname
        $hostnames = gethostbyaddr($ipv4);
        if ($hostnames !== false) {
        $hostname = is_array($hostnames) ? reset($hostnames) : $hostnames;
           echo "<p>Resolved Hostname: " . highlightText($hostname, $highlightOrg) . "</p>";
        } else {
           echo "<p>Resolved Hostname not available</p>";
        }


        // Query MX records for the domain using Net_DNS2
        require '/usr/local/php81/lib/php/Net/DNS2.php'; // Include the Net_DNS2 library
        $resolver = new Net_DNS2_Resolver();
        $mxResponse = $resolver->query($domain, 'MX');

        if ($mxResponse) {
            echo "<h2>Mail Servers (MX) for $domain:</h2>";
            echo "<ul>";
            foreach ($mxResponse->answer as $mx) {
                $exchange = highlightText($mx->exchange, $highlightOrg);
                $preference = highlightText($mx->preference, $highlightOrg);
                echo "<li><strong>Mail Exchanger:</strong> $exchange (Priority: $preference)</li>";
            }
            echo "</ul>";
        } else {
            echo "<p>Mail exchanger information not available</p>";
        }

        // Query NS records for the domain using Net_DNS2
        $nsResponse = $resolver->query($domain, 'NS');

        if ($nsResponse) {
            echo "<h2>Name Servers (NS) for $domain:</h2>";
            echo "<ul>";
            foreach ($nsResponse->answer as $ns) {
                $nsdname = highlightText($ns->nsdname, $highlightOrg);
                echo "<li><strong>Name Server:</strong> $nsdname</li>";
            }
            echo "</ul>";
        } else {
            echo "<p>Name server information not available.</p>";
        }

        // Query SPF records for the domain using dns_get_record
        $txtRecords = dns_get_record($domain, DNS_TXT);
        if ($txtRecords) {
            echo "<h2>TXT Records (SPF) for $domain:</h2>";
            echo "<ul>";
            foreach ($txtRecords as $record) {
                if (isset($record['txt']) && strpos($record['txt'], 'v=spf1') === 0) {
                    $txt = highlightText($record['txt'], $highlightOrg);
                    echo "<li><strong>TXT Record (SPF):</strong> $txt</li>";
                }
            }
            echo "</ul>";
        } else {
            echo "<p>TXT record information not availablei/set.</p>";
        }
        $dmarcRecords = dns_get_record("_dmarc." . $domain, DNS_TXT);
        if ($dmarcRecords) {
        echo "<h2>DMARC Record for $domain:</h2>";
        echo "<ul>";
        foreach ($dmarcRecords as $record) {
                if (isset($record['txt']) && strpos($record['txt'], 'v=DMARC1') === 0) {
                $dmarcTxt = highlightText($record['txt'], $highlightOrg);
                echo "<li><strong>DMARC Record:</strong> $dmarcTxt</li>";
                }
        }
        echo "</ul>";
        }       else {
        echo "<p>DMARC record information not available/set.</p>";
        }
    }
}
?>


</body>
</html>

