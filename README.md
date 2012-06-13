PercussionJasigCAS
==================

Percussion CM System authenticates visitors through JAAS; therefore, this repository introduces the instructions and code necessary to enable Jasig Central Authentication Services. 

##Notes
It is important to back up all modified XML files in the event that something does go wrong. You will also want to read the instructions attached to each XML file.

##Installation
1. Download and extract [compressed file](https://github.com/rileyw/PercussionJasigCAS/zipball/master)
2. Transfer files in **PercussionJasigCAS/lib/** to **<RHYTHMYX.DIRECTORY>/AppServer/server/rx/deploy/rxapp.ear/rxapp.war/WEB-INF/lib/**
3. Update **<RHYTHMYX.DIRECTORY>/AppServer/server/rx/conf/login-conf.xml** according to the provided login-conf.xml
4. Update **<RHYTHMYX.DIRECTORY>/AppServer/server/rx/deploy/rxapp.ear/rxapp.war/WEB-INF/web.xml** according to the provided web.xml
5. Restart Rhythmyx