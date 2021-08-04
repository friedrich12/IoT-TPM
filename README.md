# RedSGX

![redsgx](https://github.com/friedrich12/redsgx/blob/main/src/img/redsgx.png?raw=true)

RedSGX is an opensource protocol that stores files in the cloud while utilizing the power of Intel SGX, a trusted platform module. Files are encrypted on IoT devices and sent to the cloud. Files are decrypted in the TPM of a trusted PC using Intel SGX.

## Requirements

To run RedSGX, you need to have a Linux PC with a CPU that supports Intel SGX. You must install the drivers to run the SGX application on the actual hardware. 

[Install Intel SGX Drivers](https://github.com/intel/linux-sgx)

[Install Intel SGX OpenSSL Library](https://github.com/friedrich12/SGX-OpenSSL)

To run the example application, the RedSGX IoT application requires a Linux device with Video4Linux installed. Video4Linux must be enabled when building the kernel. You can find more information on how to do that [here.](https://fdoku.me/USBCamLinux/)

The OpenSSL library must be installed on the IoT device. If you are running a Linux distribution like Ubuntu, you can install it using your package manager. For embedded Linux not running a Linux distribution, it can be installed using [buildroot](https://buildroot.org/). 

Although RedSGX can run on many different cloud platforms, the current implementation only supports the Oracle NoSQL Database. A cloud server with Oracle NoSQL and NFS is needed to run the example application. It is also possible to run the cloud application locally, but you need an Oracle NoSQL Database.

## Building and Running

### Build/Run IoT Application

On the IoT device run

```bash
git clone https://github.com/friedrich12/redsgx.git
cd redsgx
cd iot
chmod a+x build.sh
./build.sh
```

The IoT Application includes a configuration file that will need to be changed.

```bash
ip=127.0.0.1                              # PUBLIC IPv4 ADDRESS OF SERVER
camera=/dev/video0                        # CAMERA DEVICE
key=2b7e151628aed2a6abf7158809cf4f3c      # AES KEY
```

### Build/Run Cloud Application

On the cloud server run

```bash
git clone https://github.com/friedrich12/redsgx.git
cd redsgx
cd cloud
cd server
go run server.go
```

There is also a DockerFile that automates this task, making it easier to deploy on servers. 

### Build/Run Intel SGX Application

On an SGX enabled PC run.

```bash
git clone https://github.com/friedrich12/redsgx.git
cd redsgx
cd cloud
cd client
chmod a+x run.sh
./run.sh
```

You will need to change the arguments in run.sh, specifically, the ip address of your IoT device and ip address of your server.

## Help

frd20@pitt.edu
