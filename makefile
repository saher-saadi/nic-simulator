CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++11

all: nic_sim.exe

nic_sim.exe: main.o L2.o L3.o L4.o NIC_sim.o
	$(CXX) $(CXXFLAGS) -o nic_sim.exe main.o L2.o L3.o L4.o NIC_sim.o

main.o: main.cpp NIC_sim.hpp
	$(CXX) $(CXXFLAGS) -c main.cpp

L2.o: L2.cpp L2.h packets.hpp common.hpp
	$(CXX) $(CXXFLAGS) -c L2.cpp

L3.o: L3.cpp L3.h packets.hpp common.hpp
	$(CXX) $(CXXFLAGS) -c L3.cpp

L4.o: L4.cpp L4.h packets.hpp common.hpp
	$(CXX) $(CXXFLAGS) -c L4.cpp

NIC_sim.o: NIC_sim.cpp NIC_sim.hpp L2.h L3.h L4.h common.hpp
	$(CXX) $(CXXFLAGS) -c NIC_sim.cpp

clean:
	rm -f *.o nic_sim.exe
