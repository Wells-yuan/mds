# MDS
MDS是一个结合区块链和零知识证明的医疗数据安全共享方案，使用fabric区块链和libsnark库实现

方案架构如下

![image-20210602095513866](img/image-20210602095513866.png)

MDS方案的测试网络结构如下，链码S1和S2分别对应`mdmanage`和`pdmanage`

![image-20210602100529917](img/image-20210602100529917.png)

需要说明的是，由于Hyperledger Fabric区块链支持私有数据的交易，MDS方案中共享服务器的功能在本实验中由维护私有数据的链码实现。加密的医疗数据和通知被授权节点新增医疗数据的消息都作为私有数据存储在peer节点的不同私有数据集合中，由链码进行访问控制。当用户需要下载医疗数据或查看是否有新增医疗数据时需要调用链码来完成操作。区块链网络中传输的私有数据不会被记录在账本中，被记录的只有私有数据的hash值，用以事务的验证

## 准备工作

### Ubuntu下搭建Fabric运行环境

| 名称         | 类型                | 版本          |
| ------------ | ------------------- | ------------- |
| 操作系统     | Linux系统           | Ubuntu  18.04 |
| 容器         | Docker              | v20.10.6      |
| 容器工具     | Docker  Compose     | v1.27.2       |
| 区块链       | Hyperledger  Fabric | v2.3.2        |
| 证书授权服务 | Hyperledger  Fabric | v1.5.0        |
| 链码编程语言 | Go语言              | v1.14         |

1. 安装git、curl、docker、go

2. 运行脚本安装Fabric Sample、docker images、和Fabric的二进制文件，运行前确保docker正在运行

   ```bash
   docker ps -a
   # 安装指定版本的Fabric v2.1.1 and Fabric CA v1.4.7
   curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.3.2 1.5.0
   ```

3. 测试网络

   ```bash
   # 启动网络
   ./network.sh up createChannel -c mychannel -ca
   # 关闭网络
   ./network.sh down
   ```



### 编译libnark库

1. 准备环境

   ```bash
   sudo apt-get install build-essential cmake git libgmp3-dev libprocps-dev python-markdown libboost-all-dev libssl-dev pkg-config
   ```

2. 编译

   ```bash
   cd ~/libsnark
   mkdir build && cd build
   cmake ..
   make
   # 生成零知识证明所需的密钥对
   ./src/produce_key
   ./src/share_key
   ./src/update_key
   ./src/access_key
   # 复制密钥对到/usr/local/prfkey
   cp -i ./*.raw /usr/local/prfKey/
   # 复制动态库到/usr/local/lib
   cp -i ./src/libzk_produce.so ./src/libzk_share.so ./src/libzk_update.so ./src/libzk_access.so ./depends/libsnark/libsnark/libsnark.so ./depends/libsnark/depends/libff/libff/libff.so /usr/local/lib
   ```



### 外部启动器构造步骤(Fabric 2.3.2)

1. 设置peer节点构建外部链码的脚本

2. 修改`fabric-samples/config/core.yaml`

   ```bash
   externalBuilders:
       - path: /opt/gopath/src/github.com/hyperledger/sampleBuilder
         name: mybuilder
   ```

3. 修改`fabric-samples/test-network/docker/docker-compose-test-net.yaml`

   ```bash
   volumes:
       - /root/bbb/fabric-samples/asset-transfer-basic/chaincode-external/sampleBuilder:/opt/gopath/src/github.com/hyperledger/sampleBuilder
       - /root/bbb/fabric-samples/mds/tmpt/core.yaml:/etc/hyperledger/fabric/core.yaml
   ```

4. 给外部链码打包信息包，安装在各个需要调用外部链码的组织上

   1. 准备好`chaincode.env`

      ```bash
      # CHAINCODE_SERVER_ADDRESS must be set to the host and port where the peer can
      # connect to the chaincode server
      CHAINCODE_SERVER_ADDRESS=mdmanage.example.com:9999
      
      # CHAINCODE_ID must be set to the Package ID that is assigned to the chaincode
      # on install. The `peer lifecycle chaincode queryinstalled` command can be
      # used to get the ID after install if required
      CHAINCODE_ID=mdmanage_1.0:6aeecdda20ee07cb527dd11c19a64cf36e117e8a0d35b0d5d9187988c3dae67c
      
      ```
      
      `CHAINCODE_SERVER_ADDRESS`指运行外部链码的网络地址
      
      `CHAINCODE_ID`指安装好的外部链码信息包的`Package ID`
      
      在外部链码源码文件的`main` 函数中，会启动一个`chaincode server`来监听该网络地址和链码包ID，完成与需要执行该外部链码的peer节点的通信
      
   2. 准备好connect.json

      ```json
      {
          "address": "mdmanage.example.com:9999",
          "dial_timeout": "10s",
          "tls_required": false
      }
      ```

      `address`为启动image时赋予的hostname和Dockerfile中暴露的端口号

   3. 准备好`metadata.json`

      ```json
      {
          "type": "external",
          "label": "mdmanage_1.0"
      }
      ```

      `type`表明该链码包是外部链码的信息包，一般`type`为链码的语言类型

      `label`就是打包链码时的标签

   4. 打包信息包

      ```bash
      # 将connection.json打包为 code.tar.gz
      tar cfz code.tar.gz connection.json
      # 将 metadata.json 和 code.tar.gz 一起打包为 链码包
      tar cfz mdmanage-external.tgz metadata.json code.tar.gz
      # 方便后续操作，将 mdmanage-external.tgz 移动到 fabric-samples/test-network/目录下
      cp mdmanage-external.tgz fabric-samples/test-network/
      ```




## 搭建MDS方案实验网络

1. 启动网络，准备链码包

   ```bash
   ./network.sh up createChannel -c mychannel -ca
   
   export PATH=${PWD}/../bin:$PATH
   export FABRIC_CFG_PATH=$PWD/../config/
   export CORE_PEER_TLS_ENABLED=true
   export CORE_PEER_LOCALMSPID="Org1MSP"
   export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
   export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
   export CORE_PEER_ADDRESS=localhost:7051
   
   peer lifecycle chaincode install mdmanage-external.tgz
   
   export CORE_PEER_LOCALMSPID="Org2MSP"
   export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
   export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp
   export CORE_PEER_ADDRESS=localhost:9051
   
   peer lifecycle chaincode install mdmanage-external.tgz
   
   export CHAINCODE_ID=mdmanage_1.0:e42ce496cca0ad2dbe7be3c3155aca0d4e32a4fe5ffabc456b9b6e004781533a
   ```

2. 准备执行外部链码的容器

   ```bash
   # 切换到/fabric-samples/mds/mydocker/
   docker build -t mds/mdmanage:1.0 .
   # 启动容器
   docker run -it --rm --name mdmanage.example.com --hostname mdmanage.example.com --env-file ./config/chaincode.env --network=fabric_test mds/mdmanage:1.0
   ```

3. 安装外部链码mdmanage

   ```bash
   export CORE_PEER_LOCALMSPID="Org2MSP"
   export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
   export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp
   export CORE_PEER_ADDRESS=localhost:9051
   
   peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "$PWD/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" --channelID mychannel --name mdmanage --version 1.0 --package-id $CHAINCODE_ID --sequence 1
   
   export CORE_PEER_LOCALMSPID="Org1MSP"
   export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
   export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
   export CORE_PEER_ADDRESS=localhost:7051
   
   peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "$PWD/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" --channelID mychannel --name mdmanage --version 1.0 --package-id $CHAINCODE_ID --sequence 1
   
   peer lifecycle chaincode commit -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "$PWD/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" --channelID mychannel --name mdmanage --peerAddresses localhost:7051 --tlsRootCertFiles "$PWD/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt" --peerAddresses localhost:9051 --tlsRootCertFiles organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt --version 1.0 --sequence 1
   ```

4. 安装私有数据维护链码pdmanage

   ```bash
   ./network.sh deployCC -ccn pdmanage -ccp ../mds/chaincode-go/pdmanage/ -ccl go -ccep "OR('Org1MSP.peer','Org2MSP.peer')" -cccg ~/fabric-samples/mds/chaincode-go/pdmanage/collections_config.json
   ```

5. 查询成功安装的链码

   ```bash
   peer lifecycle chaincode queryinstalled
   ```



### MDS方案测试

1. 注册用户

   ```bash
   export LD_LIBRARY_PATH=/usr/local/lib
   rm -r wallet/
   rm -r ../hospital/wallet/
   node enrollAdmin.js
   node registerUser.js patientA
   node registerUser.js patientB
   node registerUser.js agencyA
   go run patient.go -u patientA -f print
   cd ../hospital
   node enrollAdmin.js
   node registerUser.js hospitalA
   ```

2. 修改对应命令，进行方案测试

   ```bash
   go run hospital.go -u hospitalA -f create -p MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMmt/PAwoj52M4hAgDDm2RJ6a2RSi1nZSGdlB6oJu5uDLwHeo+oy68zgvMB8qdqeJ4ZmiCHhW4BKOLtqUScMT/Q '{"白细胞计数":"9.25", "血小板计数": "368", "血红蛋白量":"152"}'
   cd ../patient
   go run patient.go -u patientA -f check
   go run patient.go -u patientA -f access -t '{"id":"412836aa2e4afc9b9b5131415b1df07af688ca82ece2b5c661c027443cbd43b3","aux":"04905047c1816c5940e402795cbabaa3b467678a22d876765900df87e751ef5b7e2b0eadca040359846b8d349166d16854c87a5624e841460a6f263b674bc0e9d233b7680c0c67a17d963da47a3817659bd3e82ee2091816d673975e366647c5900c1a6df95b0c23819e35a23c6e80e5fef08279fdbfa178d8531323dba6918f8a4f19404d3b14e88f701a313c4a08f863846bf686acab48cfc97668f8b40979858992468681ba0d079a7b4582ba517dbdef9d6abf363054319ee0369e93f1b8c895a0d30b18cc9ecd21be4281dadf009280"}'
   go run patient.go -u patientA -f download -r '{"id":"412836aa2e4afc9b9b5131415b1df07af688ca82ece2b5c661c027443cbd43b3","r":"5140877536912537","ek":"44784b2f5dfce1b7fad7070526fced004f379a4cbf325a0f26cbbf441557c252"}'
   go run patient.go -u patientA -f share -s '{"id":"412836aa2e4afc9b9b5131415b1df07af688ca82ece2b5c661c027443cbd43b3","r":"39724891291495031","ek":"44784b2f5dfce1b7fad7070526fced004f379a4cbf325a0f26cbbf441557c252","role":"30450220646a5376db0662be985c3bd3700e7d14bdfebd45727eb80a2867d55068112bf9022100dd54e948ae2ff529ab38dfb28d7c130181c04f2cc9c956601552a6971652221b"}' -k '白细胞计数,血红蛋白量' -v MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkEZUOzU/gVz0l2x0ZJOu2Bgv+j7B3pqelazVrf5JtPynfk/h2lk8s6AQ65dE8am+9QbnZVLgCxQSyloa+fUVeA '{"白细胞计数":"9.25", "血小板计数": "368", "血红蛋白量":"152"}'
   go run patient.go -u agencyA -f check
   go run patient.go -u patientA -f update -s '{"id_B":"b58651dc10fc14af288dd672a2c9342aee97835a18871dde8e987998deeff57f","ek":"6a7d8ed99e5dfb4e1269b9b0da193e06cf3fef1817dc51fe86194d3f2810e6db","r":"60757519383210405","id_A":"412836aa2e4afc9b9b5131415b1df07af688ca82ece2b5c661c027443cbd43b3", "index":[0,2], "visitors":["MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkEZUOzU/gVz0l2x0ZJOu2Bgv+j7B3pqelazVrf5JtPynfk/h2lk8s6AQ65dE8am+9QbnZVLgCxQSyloa+fUVeA"]}' -v MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYET557h+MoF7O0Fjtc0SIB1aE2pOp9EXyWZ55VsTS8VuUBNqKk2ESxMHRYzi3zXepkrSobvXXznDzZ/0X07dmw
   go run patient.go -u patientB -f check
   ```

   