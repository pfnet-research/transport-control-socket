TARGET = cmd
SOURCES = $(wildcard *.cpp)
OBJECTS = $(SOURCES:.cpp=.o)

CXX = clang

.PHONY: all
all: $(TARGET)

.PHONY: run
run: $(TARGET)
	./cmd

.PHONY: clean
clean:
	$(RM) $(OBJECTS) $(TARGET)

%.o: %.cpp Makefile
	$(CXX) -o $@ -c $<

$(TARGET): $(OBJECTS) Makefile
	$(CXX) -o $(TARGET) $(OBJECTS)
