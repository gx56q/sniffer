<h1 align="center">Welcome to Sniffer 👋</h1>
<p>
  <a href="https://github.com/gx56q/CloudBackup/blob/master/LICENSE" target="_blank">
    <img alt="License: MIT license" src="https://img.shields.io/badge/License-MIT license-yellow.svg" />
  </a>
</p>

> Utility for sniffing traffic on the network

## Installation
To use Sniffer, follow these steps:

#### 1. Clone the repository:
```sh
git clone https://github.com/gx56q/sniffer.git
```
#### 2. Navigate to the project directory:
```sh
cd sniffer
```
#### 3. Install the required dependencies using pip:
```sh
pip install -r requirements.txt
```

## Usage

To launch Sniffer, use the following command format:

```sh
python3 main.py --output_file [path_to_output_file] --dest-port [destination_port] --dest-ip [destination_ip] --protocol [protocol]
```

### Examples

#### Basic Usage
To sniff all traffic on the network and save the results to a file:

```sh
python3 main.py 
```

#### Changing the output file
To change the output file:

```sh
python3 main.py --output_file /home/user/output.txt
```

#### Filtering by destination IP
To filter by destination IP address:

```sh
python3 main.py --dest-ip 192.168.1.1
```

#### Filtering by destination port
To filter by destination port:

```sh
python3 main.py --dest-port 80
```

#### Filtering by protocol
To filter by tcp protocol:

```sh
python3 main.py --protocol tcp
```

#### Testing the program
To test the program, you can use the following command:

```sh
python3 main.py --test
```

### Help

To get help on the available options and actions, use the `-h` or `--help` option. The command format is:

```sh
python3 main.py --help
```

## Authors

👤 **Voinov Andrey**

* Github: [@gx56q](https://github.com/gx56q)

👤 **Ratushniy Ilya**

* Github: [@dudeFromTheInternet](https://github.com/dudeFromTheInternet)

## 🤝 Contributing

Contributions, issues and feature requests are welcome!<br />Feel free to check [issues page](https://github.com/gx56q/CloudBackup/issues). 

## Show your support

Give a ⭐️ if this project helped you!

## 📝 License

Copyright © 2023 [Voinov Andrey](https://github.com/gx56q).<br />
This project is [MIT license](https://github.com/gx56q/CloudBackup/blob/master/LICENSE) licensed.

***