FROM golang:1.16

RUN git clone https://gitlab.prognosticlab.org/friedrich12/xphotondb.git

# This container exposes port 8080 to the outside world
EXPOSE 8080

RUN cd xphotondb/src/goversion/server && go mod init fdoku.me/xphotondb && go mod tidy 
CMD cd xphotondb/src/goversion/server && go run server.go


