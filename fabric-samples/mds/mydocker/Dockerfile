FROM ubuntu:18.04
RUN  sed -i s@/archive.ubuntu.com/@/mirrors.aliyun.com/@g /etc/apt/sources.list
RUN apt-get update -y && \  
     apt-get install -y libgmp3-dev
COPY ./lib/ /usr/local/lib/
COPY ./prfKey/ /usr/local/prfKey/
ENV LD_LIBRARY_PATH /usr/local/lib
COPY ./external/chaincode /external/
WORKDIR /external
EXPOSE 9999
CMD ["./chaincode"]
