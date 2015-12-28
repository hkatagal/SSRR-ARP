Authors: Harishkumar Katagal(109915793) & Gagan Nagaraju (109889036)
CSE 533 - Assignment 4
********************************************************************************************

USER DOCUMENTATION:

Following are the files that contain the source codes for the assignment 4.
arp_hkatagal.c
arp_hkatagal.h
get_hw_addrs.c
hw_addrs.h
tour_hkatagal.c
tour_hkatagal.h
Makefile



To compile and generate executables use the "Makefile" and issue a "make". This will generate the *.o and the executable files. The two main important files that we want are "arp_hkatagal", and "tour_hkatagal". Use these two files to run the arp and tour applications respectively. To run the arp use "./arp_hkatagal" command, this will start the arp and creates listening socket. To run the tour use "./tour_hkatagal". Specify the tour vm name parameters as argument to run this program.
Some sample examples are shown below.

Ex1:   	./arp_hkatagal
		./tour_hkatagal vm1 vm2 vm3
	   
Note: When you issue make, you might get some warnings like "warning: assignment from incompatible pointer type", these can be safely ignored.

Output:
All the messages from the arp and tour are displayed in their corresponding terminals.

**************************************************************************************************
