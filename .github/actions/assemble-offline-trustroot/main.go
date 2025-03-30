package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

func main() {
	// Configure the logger to write to stderr
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)

	// Declare CLI inputs with default values
	outputFilename := flag.String("output-trustroot-filename", "trustroot.yaml", "The name of the output TrustRoot file")
	templateFilePath := flag.String("template-filename", "", "The path to the template file")
	trustedRootPath := flag.String("trusted-root-path", "", "The path to the trusted_root.json file")
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
	log.Printf("Output Filename: %s", *outputFilename)
	log.Printf("Organization: %s", *organization)
	log.Printf("Common Name: %s", *commonName)
	log.Printf("URI: %s", *uri)

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

	// Create a temporary file for the YAML copy
	tempFile, err := os.CreateTemp("", fmt.Sprintf("%s-*.yaml", *outputFilename))
	if err != nil {
		log.Fatalf("Error creating temporary file: %v", err)
	}
	defer os.Remove(tempFile.Name()) // Clean up the temporary file

	// Copy the template file to the temporary file
	if err := copyFile(*templateFilePath, tempFile.Name()); err != nil {
		log.Fatalf("Error copying template file: %v", err)
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

				// Convert to PEM format using openssl
				pem, err := convertToPEM(decoded)
				if err != nil {
					log.Printf("Error converting to PEM for %s[%d][%d]: %v", authority, i, j, err)
					continue
				}

				pemData.WriteString(pem)
			}

			// Encode the full PEM chain to base64
			certChain := base64.StdEncoding.EncodeToString([]byte(pemData.String()))

			// Update the temporary YAML file using yq
			updateYAML(tempFile.Name(), authority, i, *organization, *commonName, *uri, certChain)
		}
	}

	// Write the final temporary file to the specified output file
	finalContent, err := os.ReadFile(tempFile.Name())
	if err != nil {
		log.Fatalf("Error reading temporary file: %v", err)
	}
	if err := os.WriteFile(*outputFilename, finalContent, 0644); err != nil {
		log.Fatalf("Error writing to output file: %v", err)
	}
	log.Printf("Output written to %s", *outputFilename)
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, input, 0644)
}

// convertToPEM converts raw certificate bytes to PEM format using openssl
func convertToPEM(cert []byte) (string, error) {
	cmd := exec.Command("openssl", "x509", "-inform", "DER", "-outform", "PEM")
	cmd.Stdin = strings.NewReader(string(cert))
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// updateYAML updates the YAML file using yq
func updateYAML(filename, authority string, index int, organization, commonName, uri, certChain string) {
	exec.Command("yq", "eval", fmt.Sprintf(".spec.sigstoreKeys.%s[%d].subject = {}", authority, index), filename, "-i").Run()
	exec.Command("yq", "eval", fmt.Sprintf(".spec.sigstoreKeys.%s[%d].subject.organization = \"%s\"", authority, index, organization), filename, "-i").Run()
	exec.Command("yq", "eval", fmt.Sprintf(".spec.sigstoreKeys.%s[%d].subject.commonName = \"%s\"", authority, index, commonName), filename, "-i").Run()
	exec.Command("yq", "eval", fmt.Sprintf(".spec.sigstoreKeys.%s[%d].uri = \"%s\"", authority, index, uri), filename, "-i").Run()
	exec.Command("yq", "eval", fmt.Sprintf(".spec.sigstoreKeys.%s[%d].certChain = \"%s\"", authority, index, certChain), filename, "-i").Run()
}
