TARGET = cmd
SOURCES = $(wildcard *.cpp)
OBJECTS = $(SOURCES:.cpp=.o)

CXX = clang

NC_PORT = 10101

.PHONY: all
all: $(TARGET)

.PHONY: run-client
run-client: $(TARGET)
	./cmd localhost $(NC_PORT)

.PHONY: run-server
run-server: $(TARGET)
	./cmd -l $(NC_PORT)

.PHONY: clean
clean:
	$(RM) $(OBJECTS) $(TARGET)

%.o: %.cpp Makefile
	$(CXX) -o $@ -c $<

$(TARGET): $(OBJECTS) Makefile
	$(CXX) -o $(TARGET) $(OBJECTS)
