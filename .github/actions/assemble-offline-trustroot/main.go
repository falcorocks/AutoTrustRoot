package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

func main() {
	// Configure the logger to write to stderr
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)

	// Declare CLI inputs with default values
	outputFilepath := flag.String("output-trustroot-filepath", "/tmp/trustroot.yaml", "The name of the output TrustRoot file")
	templateFilePath := flag.String("template-filepath", "trustroot.template.yaml", "The path to the template file")
	trustedRootPath := flag.String("trusted-root-path", "~/.sigstore/root/targets/trusted_root.json", "The path to the trusted_root.json file")
	organization := flag.String("organization", "GitHub, Inc.", "The organization name")
	commonName := flag.String("commonName", "Internal Services Root", "The common name")
	uri := flag.String("uri", "https://fulcio.githubapp.com", "The URI")

	// Parse the CLI flags
	flag.Parse()

	// Validate required inputs
	if *templateFilePath == "" {
		log.Fatalf("The --template-filename flag is required")
	}
	if *trustedRootPath == "" {
		log.Fatalf("The --trusted-root-path flag is required")
	}

	// Log the values
	log.Printf("Template File Path: %s", *templateFilePath)
	log.Printf("Trusted Root Path: %s", *trustedRootPath)
	log.Printf("Output Filename: %s", *outputFilepath)
	log.Printf("Organization: %s", *organization)
	log.Printf("Common Name: %s", *commonName)
	log.Printf("URI: %s", *uri)

	// Clear the contents of the output file by truncating it
	if err := os.Truncate(*outputFilepath, 0); err != nil {
		if !os.IsNotExist(err) {
			log.Fatalf("Error truncating output file: %v", err)
		}
		// If the file does not exist, create it
		if _, err := os.Create(*outputFilepath); err != nil {
			log.Fatalf("Error creating output file: %v", err)
		}
	}

	// Copy the template file to the output file
	if err := copyFile(*templateFilePath, *outputFilepath); err != nil {
		log.Fatalf("Error copying template file: %v", err)
	}

	// Open the trusted_root.json file
	file, err := os.Open(*trustedRootPath)
	if err != nil {
		log.Fatalf("Error opening trusted_root.json: %v", err)
	}
	defer file.Close()

	// Parse the JSON file into a map
	var trustedRoot map[string]interface{}
	if err := json.NewDecoder(file).Decode(&trustedRoot); err != nil {
		log.Fatalf("Error decoding trusted_root.json: %v", err)
	}

	// Iterate over "certificateAuthorities" and "timestampAuthorities"
	for _, authority := range []string{"certificateAuthorities", "timestampAuthorities"} {
		authorities, ok := trustedRoot[authority].([]interface{})
		if !ok {
			log.Printf("No %s found in trusted_root.json", authority)
			continue
		}

		log.Printf("There are %d %s", len(authorities), authority)

		for i := 0; i < len(authorities); i++ {
			authorityData, ok := authorities[i].(map[string]interface{})
			if !ok {
				log.Printf("Invalid data for %s[%d]", authority, i)
				continue
			}

			// Process the certificate chain
			certChainData, ok := authorityData["certChain"].(map[string]interface{})
			if !ok {
				log.Printf("No certChain found for %s[%d]", authority, i)
				continue
			}

			certificates, ok := certChainData["certificates"].([]interface{})
			if !ok {
				log.Printf("No certificates found for %s[%d]", authority, i)
				continue
			}

			var pemData strings.Builder
			for j := 0; j < len(certificates); j++ {
				cert, ok := certificates[j].(map[string]interface{})
				if !ok {
					log.Printf("Invalid certificate data for %s[%d][%d]", authority, i, j)
					continue
				}

				rawBytes, ok := cert["rawBytes"].(string)
				if !ok {
					log.Printf("No rawBytes found for %s[%d][%d]", authority, i, j)
					continue
				}

				decoded, err := base64.StdEncoding.DecodeString(rawBytes)
				if err != nil {
					log.Printf("Error decoding base64 for %s[%d][%d]: %v", authority, i, j, err)
					continue
				}

				// Convert to PEM format using crypto/x509
				pem, err := convertToPEM(decoded)
				if err != nil {
					log.Printf("Error converting to PEM for %s[%d][%d]: %v", authority, i, j, err)
					continue
				}

				pemData.WriteString(pem)
			}

			// Encode the full PEM chain to base64
			certChain := base64.StdEncoding.EncodeToString([]byte(pemData.String()))

			// Update the output YAML file using yaml.v3
			if err := updateYAML(*outputFilepath, authority, i, *organization, *commonName, *uri, certChain); err != nil {
				log.Printf("Error updating YAML for %s[%d]: %v", authority, i, err)
			}
		}
	}

	log.Printf("Output written to %s", *outputFilepath)
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, input, 0644)
}

// convertToPEM converts raw certificate bytes to PEM format using the crypto/x509 package
func convertToPEM(cert []byte) (string, error) {
	// Parse the certificate to ensure it's valid
	_, err := x509.ParseCertificate(cert)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Encode the certificate in PEM format
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}
	var pemData strings.Builder
	if err := pem.Encode(&pemData, pemBlock); err != nil {
		return "", fmt.Errorf("failed to encode certificate to PEM: %w", err)
	}

	return pemData.String(), nil
}

// updateYAML updates the YAML file directly using the yaml.v3 package
func updateYAML(filename, authority string, index int, organization, commonName, uri, certChain string) error {
	// Read the existing YAML file
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read YAML file: %w", err)
	}

	// Parse the YAML into a map
	var root map[string]interface{}
	if err := yaml.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Navigate to the spec.sigstoreKeys section
	spec, ok := root["spec"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("missing 'spec' section in YAML")
	}

	sigstoreKeys, ok := spec["sigstoreKeys"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("missing 'sigstoreKeys' section in YAML")
	}

	// Get or create the authority list
	authorityList, ok := sigstoreKeys[authority].([]interface{})
	if !ok {
		authorityList = make([]interface{}, index+1)
		sigstoreKeys[authority] = authorityList
	}

	// Ensure the list is large enough
	for len(authorityList) <= index {
		authorityList = append(authorityList, map[string]interface{}{})
	}
	sigstoreKeys[authority] = authorityList

	// Update the specific authority entry
	entry, ok := authorityList[index].(map[string]interface{})
	if !ok {
		entry = map[string]interface{}{}
		authorityList[index] = entry
	}

	entry["subject"] = map[string]interface{}{
		"organization": organization,
		"commonName":   commonName,
	}
	entry["uri"] = uri
	entry["certChain"] = certChain

	// Marshal the updated YAML back to a string
	updatedData, err := yaml.Marshal(root)
	if err != nil {
		return fmt.Errorf("failed to marshal updated YAML: %w", err)
	}

	// Write the updated YAML back to the file
	if err := os.WriteFile(filename, updatedData, 0644); err != nil {
		return fmt.Errorf("failed to write updated YAML file: %w", err)
	}

	return nil
}
