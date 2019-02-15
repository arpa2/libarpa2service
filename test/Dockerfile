# Test ARPA2 Tier 1 platform: Debian Stable, which is currently Stretch
# Run from repository root dir: docker build -t liba2 . -f test/Dockerfile

FROM debian:stretch

RUN apt-get update && apt-get install -y \
	man \
	gcc \
	cmake

RUN apt-get install -y \
	liblmdb-dev \
	git \
	nvi \
	tmux

#RUN git clone https://github.com/arpa2/libarpa2service.git
COPY . libarpa2service
RUN rm -rf libarpa2service/build/*

RUN cd libarpa2service/build && \
	cmake .. && \
	make && \
	make install && \
	ldconfig

RUN cd libarpa2service/build && \
	ctest
