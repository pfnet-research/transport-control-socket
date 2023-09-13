TARGET = cmd
SOURCES = $(wildcard *.cpp)
OBJECTS = $(SOURCES:.cpp=.o)

CXX = clang

.PHONY: all
all: $(TARGET)

.PHONY: run-client
run-client: $(TARGET)
	./cmd localhost 10101

.PHONY: run-server
run-server: $(TARGET)
	./cmd -l 10101

.PHONY: clean
clean:
	$(RM) $(OBJECTS) $(TARGET)

%.o: %.cpp Makefile
	$(CXX) -o $@ -c $<

$(TARGET): $(OBJECTS) Makefile
	$(CXX) -o $(TARGET) $(OBJECTS)
