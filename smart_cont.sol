// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract BlockchainDNS {
    // Structure to hold domain details
    struct Domain {
        bytes32 domainHash;   // Hash of the domain name and IP address
        address owner;        // Owner of the domain
        uint256 timestamp;    // Registration time
        string ipAddress;     // IP address associated with the domain
        uint256 expiryTime;   // Expiry time of the domain
        string canonicalName; // Canonical name (CNAME) for the domain
    }
      // Structure to hold email details
    struct Email {
        string emailAddress; // Registered email address
        string ipAddress;    // Associated IP address for the email
    }

    // Mapping from domain name to Domain structure
    mapping(string => Domain) private domains;

    // Mapping from canonical name to domain name
    mapping(string => string) private cnameToDomain;

    // Mapping from email address to Email structure
    mapping(string => Email) private emails;

   

   
    // Events
    event DomainRegistered(string indexed domain, bytes32 domainHash, address indexed owner, string canonicalName);
    event DomainUpdated(string indexed domain, bytes32 newDomainHash, string newCanonicalName);
    event DomainTransferred(string indexed domain, address indexed oldOwner, address indexed newOwner);
    event DomainDeleted(string indexed domain, address indexed owner);
    event EmailRegistered(string indexed email, string ipAddress);
    event EmailValidated(string indexed email, bool isValid);

    // Modifiers
    modifier onlyOwner(string memory domain) {
        require(
            msg.sender == domains[domain].owner,
            "Only the domain owner can perform this action"
        );
        _;
    }

    modifier notExpired(string memory domain) {
        require(block.timestamp <= domains[domain].expiryTime, "Domain has expired");
        _;
    }
modifier validDomainLength(string memory domain) {
    bytes memory domainBytes = bytes(domain);

    // Rules:
    // 1. Domain name must be between 4 and 255 characters.
    require(domainBytes.length >= 4 && domainBytes.length <= 255, "Domain length is invalid");

    // 2. Domain must start with a letter or a digit and must end with a letter or a digit.
  /*  require(
        isAlphaNumeric(domainBytes[0]) && isAlphaNumeric(domainBytes[domainBytes.length - 1]),
        "Domain must start and end with an alphanumeric character"
    );

    // 3. Intermediate characters can include letters, digits, hyphens ('-'), but not consecutive hyphens.
    for (uint256 i = 1; i < domainBytes.length - 1; i++) {
        require(
            isAlphaNumeric(domainBytes[i]) || domainBytes[i] == 0x2D, // 0x2D is '-'
            "Invalid character in domain"
        );

        // Check for consecutive hyphens
        require(!(domainBytes[i] == 0x2D && domainBytes[i - 1] == 0x2D), "Consecutive hyphens are not allowed");
    }*/

    _;
}

function isAlphaNumeric(bytes1 char) internal pure returns (bool) {
    return (char >= 0x30 && char <= 0x39) || // '0'-'9'
           (char >= 0x41 && char <= 0x5A) || // 'A'-'Z'
           (char >= 0x61 && char <= 0x7A);   // 'a'-'z'
        
}


    // Helper functions
    function generateDomainHash(string memory domain, string memory ipAddress) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(domain, ipAddress));
    }

    function split(string memory str, bytes1 delimiter) internal pure returns (string[] memory) {
        bytes memory strBytes = bytes(str);
        uint256 splitsCount = 1;
        for (uint256 i = 0; i < strBytes.length; i++) {
            if (strBytes[i] == delimiter) splitsCount++;
        }
        string[] memory parts = new string[](splitsCount);
        uint256 partsIndex = 0;
        bytes memory buffer = "";

        for (uint256 i = 0; i < strBytes.length; i++) {
            if (strBytes[i] == delimiter) {
                parts[partsIndex++] = string(buffer);
                buffer = ""; // Reset the buffer
            } else {
                buffer = abi.encodePacked(buffer, strBytes[i]); // Append byte to buffer
            }
        }
        parts[partsIndex] = string(buffer); // Add the last part
        return parts;
    }

    function toUint(string memory str) internal pure returns (uint256) {
        bytes memory bStr = bytes(str);
        uint256 result = 0;
        for (uint256 i = 0; i < bStr.length; i++) {
            require(bStr[i] >= 0x30 && bStr[i] <= 0x39, "Invalid character in IP segment");
            result = result * 10 + (uint8(bStr[i]) - 48);
        }
        return result;
    }

    // Validate IPv4 address function
    function validateIPv4Address(string memory ipAddress) internal pure returns (bool) {
        string[] memory octets = split(ipAddress, '.');
        if (octets.length != 4) return false; // Must have 4 octets

        uint256 firstOctet = toUint(octets[0]);
        uint256 secondOctet = toUint(octets[1]);
        uint256 thirdOctet = toUint(octets[2]);
        uint256 fourthOctet = toUint(octets[3]);

        if (firstOctet > 255 || secondOctet > 255 || thirdOctet > 255 || fourthOctet > 255) {
            return false; // All octets must be in the range 0-255
        }

        return true;
    }

    // Validate Class A or Class B IP address with network and host checks
    function validateClassAorB(string memory ipAddress) internal pure returns (string memory) {
        string[] memory octets = split(ipAddress, '.');
        uint256 firstOctet = toUint(octets[0]);
        uint256 secondOctet = toUint(octets[1]);
        uint256 thirdOctet = toUint(octets[2]);
        uint256 fourthOctet = toUint(octets[3]);

        // Class A (1.0.0.1 to 100.255.255.100)
        if (firstOctet >= 1 && firstOctet <= 100) {
            if (
                (firstOctet == 100 && (secondOctet > 255 || thirdOctet > 255 || fourthOctet > 100)) || 
                (firstOctet == 100 && secondOctet == 255 && thirdOctet == 255 && fourthOctet > 100)
            ) {
                return "Invalid Class A IP range";
            }
            return "Valid Class A IP range";
        }

        // Class B (128.0.0.1 to 170.255.255.150)
        if (firstOctet >= 128 && firstOctet <= 170) {
            if (
                (firstOctet == 170 && secondOctet > 255) || 
                (firstOctet == 170 && secondOctet == 255 && thirdOctet > 255) || 
                (firstOctet == 170 && secondOctet == 255 && thirdOctet == 255 && fourthOctet > 150)
            ) {
                return "Invalid Class B IP range";
            }
            return "Valid Class B IP range";
        }

        return "Invalid IP class (Not Class A or Class B)";
    }

    // Main functions
    function registerDomain(
        string memory domain,
        string memory ipAddress,
        string memory canonicalName,
        uint256 duration
    ) public validDomainLength(domain) {
        require(domains[domain].owner == address(0), "Domain already registered");

        // Validate the IPv4 address format (No class validation here)
        require(validateIPv4Address(ipAddress), "Invalid IPv4 address format");

        bytes32 domainHash = generateDomainHash(domain, ipAddress);
        domains[domain] = Domain({
            domainHash: domainHash,
            owner: msg.sender,
            timestamp: block.timestamp,
            ipAddress: ipAddress,
            expiryTime: block.timestamp + duration,
            canonicalName: canonicalName
        });
        cnameToDomain[canonicalName] = domain;

        emit DomainRegistered(domain, domainHash, msg.sender, canonicalName);
    }

    function updateDomain(
        string memory domain,
        string memory newIpAddress,
        string memory newCanonicalName
    ) public onlyOwner(domain) {
        Domain storage domainRecord = domains[domain];

        // Validate new IP address
        require(validateIPv4Address(newIpAddress), "Invalid IPv4 address format");

        // Validate Class A or Class B IP range
        string memory ipClassValidation = validateClassAorB(newIpAddress);
        require(keccak256(abi.encodePacked(ipClassValidation)) == keccak256(abi.encodePacked("Valid Class A IP range")) ||
                keccak256(abi.encodePacked(ipClassValidation)) == keccak256(abi.encodePacked("Valid Class B IP range")) ||
                keccak256(abi.encodePacked(ipClassValidation)) == keccak256(abi.encodePacked("Invalid IP class (Not Class A or Class B)")) ,
                ipClassValidation);

        // Update IP address and canonical name
        domainRecord.ipAddress = newIpAddress;
        domainRecord.canonicalName = newCanonicalName;

        // Recalculate the domain hash
        bytes32 newDomainHash = generateDomainHash(domain, newIpAddress);
        domainRecord.domainHash = newDomainHash;

        // Emit event for domain update
        emit DomainUpdated(domain, newDomainHash, newCanonicalName);
    }

    function validateDomain(string memory input)
        public
        view
        returns (bool, string memory, string memory, string memory)
    {
        string memory domain;
        if (domains[input].owner != address(0)) {
            domain = input;
        } else if (bytes(cnameToDomain[input]).length > 0) {
            domain = cnameToDomain[input];
        } else {
            return (false, "Input is neither a registered domain nor a canonical name", "", "");
        }

        Domain storage domainRecord = domains[domain];
        if (block.timestamp > domainRecord.expiryTime) return (false, "Domain has expired", "", "");

        // Validate Class A or Class B IP range
        string memory ipClassValidation = validateClassAorB(domainRecord.ipAddress);

        // Check if IP address is within valid Class A or Class B ranges
        if (keccak256(abi.encodePacked(ipClassValidation)) != keccak256(abi.encodePacked("Valid Class A IP range")) &&
            keccak256(abi.encodePacked(ipClassValidation)) != keccak256(abi.encodePacked("Valid Class B IP range"))) {
            return (false, ipClassValidation, "", ""); // Return false and no IP address
        }

        return (true, domain, domainRecord.canonicalName, domainRecord.ipAddress); // Return true with IP address
    }

    // Function to delete a domain
    function deleteDomain(string memory domain) public onlyOwner(domain) {
        delete cnameToDomain[domains[domain].canonicalName];
        delete domains[domain];

        emit DomainDeleted(domain, msg.sender);
    }

    // Function to transfer ownership of a domain
    function transferOwnership(string memory domain, address newOwner) public onlyOwner(domain) {
        require(newOwner != address(0), "New owner cannot be the zero address");
        address oldOwner = domains[domain].owner;
        domains[domain].owner = newOwner;

        emit DomainTransferred(domain, oldOwner, newOwner);
    }


        // Function to register an email address
    function registerEmail(string memory email, string memory ipAddress) public {
        // Ensure email is not already registered
        require(bytes(emails[email].emailAddress).length == 0, "Email already registered");

        // Register the email and IP address
        emails[email] = Email({
            emailAddress: email,
            ipAddress: ipAddress
        });

        emit EmailRegistered(email, ipAddress);
    }

    // Function to validate email address
    function validateEmail(string memory email) public view returns (bool, string memory, string memory) {
        if (bytes(emails[email].emailAddress).length == 0) {
            return (false, "Email not registered", ""); // Return an empty string for IP address if not registered
        }

        // Check if email is from @kletech.ac.in
        if (isValidKletechEmail(email)) {
            return (true, emails[email].emailAddress, emails[email].ipAddress);
        } else {
            return (false, "Email domain is not valid. Only @kletech.ac.in is allowed", "");
        }
    }

    // Helper function to check if the email domain is @kletech.ac.in
    function isValidKletechEmail(string memory email) internal pure returns (bool) {
        string[] memory parts = split(email, '@');
        if (parts.length != 2) return false; // Invalid email format
        return keccak256(abi.encodePacked(parts[1])) == keccak256(abi.encodePacked("kletech.ac.in"));
    }
}