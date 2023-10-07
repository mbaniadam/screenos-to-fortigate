# Juniper ScreenOS to FortiGate Configuration Converter
This is a Python script that converts Juniper ScreenOS firewall policies, addresses, address groups and custom ports to Fortigate firewall configuration. It takes a txt backup file of Juniper ScreenOS firewall configuration as input and generates Fortigate configuration commands in a text file.

This script supports the conversion of the following cases:

- Firewall policies
- Addresses
- Address groups
- Custom ports
  
## Usage

1- **Parse the Original Configuration:**

   Before converting Juniper ScreenOS configurations to Fortigate format, you need to parse the original configuration file using `parser.py`. Make sure you have the original configuration file named `origin_config.txt` in the **input** directory. Run the following command:

```bash
   python parser.py
```
This will generate a parsed_config.json file containing the parsed configuration.

2- **Convert and Write the Configuration:**

Once you have the parsed JSON configuration, you can convert it to Fortigate format using builder.py. Run the following command:

``` bash
python builder.py
```
This will generate a converted_config.txt file containing the Fortigate configuration.

Review the converted_config.txt file carefully to ensure that the conversion is accurate and meets your specific Fortigate configuration requirements.

## Acknowledgements

Special thanks to [Mr. Siem Hermans](https://github.com/siemhermans) for their invaluable `screenos-config-parser` repository, which greatly assisted in parsing Juniper ScreenOS configurations to JSON format for this project.

Repository Link: [screenos-config-parser](https://github.com/siemhermans/screenos-config-parser)
