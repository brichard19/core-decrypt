OUTPUT=../core-decrypt.bin
CXX=g++
CXXFLAGS=-O2 -std=c++11
OPENCL_VERSION=120
OPENCL_INCLUDE=/usr/local/cuda-9.2/include
OPENCL_LIBS=/usr/local/cuda-9.2/lib64
LIBS=-lOpenCL

all:
	${CXX} embedcl/embedcl.cpp -o embedcl.bin
	./embedcl.bin core-decrypt.cl core-decrypt_cl.cpp _core_decrypt_cl
	${CXX} ${CXXFLAGS} *.cpp -o ${OUTPUT} -L${OPENCL_LIBS} -L${OPENCL_INCLUDE} ${LIBS} -DCL_TARGET_OPENCL_VERSION=${OPENCL_VERSION}

clean:
	rm -rf ${OUTPUT}
