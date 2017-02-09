# Organized Peer-to-Peer Networking

Abstract
========
Accessing devices on a local network has become challenging with the development of the Internet. Recent shifts to cloud-based services, has overseen the need to access these devices, such as printer and cameras. Apart from accessing them, doing this in an e cient manner is also a challenge. This project proposes a peer-to-peer based solution, which will allow for communicating with a local device through a cloud-service. Because of the nature of the peer-to-peer system, it will also allows for high performance gains and reduced operation costs by distributing workload.

Code
====
The code is here only for the sake of the report. It is most likely not of any value, neither as for teaching Rust, nor as a production-quality system. This code is the absolute, very first code I wrote in Rust, so it should not surprise anyone, if it does not follow idiomatic Rust guidelines.

Reflection
==========
What would be the future of this project? Sadly, looking from a completely objective point of view, this project is a band-aid on a fractured bone. This project tries to accomplish something, which should be solved by the underlying design of the Internet. The effort, which I put into circumventing security features, might have been better used on fixing the underlying problem: The Internet itself. The Internet grew from a very technical perspective of “what is possible”. Now that we have proved it works, maybe we should start to look at what we want from the Internet.

Does it really have to be as hard as rocket science to allow for yourself to access your webcam from work? Could we possibly engage the user in IT-security in a light fashion?

We have the Internet, which is inherently hostile, but we do not have a one-size-fits-all cure for solving the problem. It’s completely up to the individual server host to make sure to enable encryption, because it’s a technology which has been patched on-top. Maybe we need technologies like PGP and a web-of-trust to be more influential on a low-level IP-basis. It would vastly change the view of IT-security, if every household and company, could manage access to its network by ‘simply’ signing an end-user’s certificate. It does not have to be a centralized government-control system, but rather in the line of the way key-based authentication works on SSH. You construct a key and tell people about it.

Until the underlying problem is solved, there might be a place in the world for a system like this. Given the right resources, we might see a project similar to this in the futuristic Internet-of-Things. When you want to turn on the air-conditioner while driving home, or turn on the toaster from work, you’ll need some way to connect to these devices. The way to solve it today, will be up to the individual manufacturer of the device. One would hope this does not lead to fragmentation, where you need one website or program to control each device. The need for standardized ways to interconnect these things, will likely grow by the years.
