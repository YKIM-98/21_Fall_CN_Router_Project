# 2019CSECNU-Computer-Network-01-Router
Router

##### Routing Table

```
Destination : Byte[4]
NetMask : Byte[6]
GateWay : Byte[4]
Flag : Boolean[3]
Interface : String
Metric : Int
```

프로그램이 실행되었을 때 연결되어 있는 모든 장치에 GARP 보내기

##### 2019-11-14 Router 첫 회의

FLAG chmod 처럼 1+2+4를 이용해 표시

github repo 만들고 지난 ARP 과제를 참고해 skeleton code를 repo에 push



##### 2019-11-15 Router 수업 끝난 후 회의

Subnet mask byte[]? int? => int

프로그램 켜질 때 GARP 보내기



##### 2019-11-25 Router 2번째 회의

GUI 연결 확인, (TCPLayer, FileAppLayer, ChatAppLayer, TimerUtillity) 삭제 => github에 업로드

2개의 NI, 2개의 IP => Dlg를 제외하고 모든 Layer 객체를 2개씩 생성하기로 함.

RoutingTable에서 RoutingRow를 만드는 메소드 getRoutingTableRow() 을 통해 Table에 add할 때 flags의 Radio Button 값을 통해 ADD해줌.

table에 Sorting하여 Longest Prefix Rule로 먼저 매칭되도록 add

NetMasking 구현

