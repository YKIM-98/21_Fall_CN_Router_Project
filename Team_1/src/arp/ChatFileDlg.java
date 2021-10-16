package arp;

import java.awt.Container;
import java.awt.FileDialog;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import javax.sound.sampled.AudioFormat.Encoding;
import javax.swing.*;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.border.EtchedBorder;

import java.awt.Color;

public class ChatFileDlg extends JFrame implements BaseLayer {
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();

	String path;

	private static LayerManager m_LayerMgr = new LayerManager();
	int selected_index = 0; // 미 초기화 시 오류
	private JTextField ChattingWrite;
	private JTextField FileDir_path;
	JTextField hwAddress;

	Container contentPane;

	JTextArea ChattingArea;
	JTextArea srcMacAddress;
	JTextArea dstMacAddress;

	JLabel lblSelectNic;
	JLabel lblsrc;
	JLabel lbldst;
	JLabel lblhw;

	JButton Setting_Button;
	JButton File_select_Button;
	JButton Chat_send_Button;
	JButton NIC_select_Button;
	JButton File_send_Button;
	JButton HwAddress_send_Button;

	JComboBox comboBox;

	FileDialog fd;
	private JTextField ARPIpAddress;
	private JPanel panel_1;
	private JLabel lblIpaddr_1;
	private JTextField PARPDevice;
	private JLabel lblIpaddr_2;
	private JTextField PARPIpAddress;
	private JLabel lblIpaddr_3;
	private JTextField PARPMacAddress;
	private JButton Proxy_Entry_Add_Button;
	private JButton Proxy_Entry_Delete_Button;
	private JPanel panel_2;
	private JTable Table_ARP_Cache;

	InetAddress myIPAddress = null;
	private JTable Table_PARP_Entry;

	public static void main(String[] args) {
		m_LayerMgr.AddLayer(new NILayer("NI"));
		m_LayerMgr.AddLayer(new EthernetLayer("Ethernet"));
		m_LayerMgr.AddLayer(new ARPLayer("ARP"));
		m_LayerMgr.AddLayer(new IPLayer("IP"));
		m_LayerMgr.AddLayer(new TCPLayer("TCP"));
		m_LayerMgr.AddLayer(new ChatAppLayer("Chat"));
		m_LayerMgr.AddLayer(new FileAppLayer("File"));
		m_LayerMgr.AddLayer(new ChatFileDlg("GUI"));

		m_LayerMgr.ConnectLayers(" NI ( *Ethernet ( *IP ( *TCP ( *Chat ( *GUI ) *File ) -ARP ) *ARP ) )");
	}

	public ChatFileDlg(String pName) {

		pLayerName = pName;
		setTitle("1조 컴퓨터네트워크 ARP 팀프로젝트");

		setBounds(250, 250, 1351, 575);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

		contentPane = this.getContentPane();
		JPanel pane = new JPanel();

		pane.setLayout(null);
		contentPane.add(pane);

		// This is a table for ARP Cache
		// Needed in order to implement "Item Delete"
		String header_ARP_Cache[] = { "IP주소", "MAC주소", "완료 여부" };
		String contents_ARP_Cache[][] = {

//				{"123.123.123.123", "AA-BB-CC-11-22-33", "complete"},
//				{"234", "zxc", "n"}
		};

		String header_PARP_Entry[] = { "Device", "IP_주소", "MAC_주소" };
		String contents_PARP_Entry[][] = {

//				{"HostA", "123.123.123.123", "AA-BB-CC-11-22-33"},
//				{"234", "zxc", "n"}
		};

		DefaultTableModel dtm_ARP = new DefaultTableModel(contents_ARP_Cache, header_ARP_Cache);

		Table_ARP_Cache = new JTable(dtm_ARP);
		Table_ARP_Cache.setBounds(597, 66, 314, 136);
		JScrollPane scrollpane_ARP = new JScrollPane(Table_ARP_Cache);
		scrollpane_ARP.setSize(350, 367);
		scrollpane_ARP.setLocation(580, 50);
//		pane.add(table);
		pane.add(scrollpane_ARP);

		DefaultTableModel dtm_PARP = new DefaultTableModel(contents_PARP_Entry, header_PARP_Entry);

		Table_PARP_Entry = new JTable(dtm_PARP);
		Table_PARP_Entry.setBounds(958, 38, 350, 226);
		JScrollPane scrollpane_PARP = new JScrollPane(Table_PARP_Entry);
		scrollpane_PARP.setSize(350, 275);
		scrollpane_PARP.setLocation(958, 50);
		pane.add(scrollpane_PARP);
//		pane.add(Table_PARP_Entry);

		lblIpaddr_1 = new JLabel("Device");
		lblIpaddr_1.setBounds(1009, 353, 58, 20);
		pane.add(lblIpaddr_1);

		PARPDevice = new JTextField();
		PARPDevice.setColumns(10);
		PARPDevice.setBounds(1079, 353, 183, 20);
		pane.add(PARPDevice);

		ChattingArea = new JTextArea();
		ChattingArea.setEditable(false);
		ChattingArea.setBounds(26, 38, 345, 226);
		pane.add(ChattingArea);// 채팅

		srcMacAddress = new JTextArea();
//		srcMacAddress.setEditable(false);
		srcMacAddress.setBounds(383, 148, 170, 24);
		pane.add(srcMacAddress);// 보내는 주소

		dstMacAddress = new JTextArea();
		dstMacAddress.setBounds(383, 207, 170, 24);
		pane.add(dstMacAddress);// 받는 사람 주소

		ChattingWrite = new JTextField();
		ChattingWrite.setBounds(26, 274, 345, 20);// 249
		pane.add(ChattingWrite);
		ChattingWrite.setColumns(10);// 채팅 쓰는 곳

		FileDir_path = new JTextField();
		FileDir_path.setEditable(false);
		FileDir_path.setBounds(26, 305, 518, 20); // 280
		pane.add(FileDir_path);
		FileDir_path.setColumns(10);// file 경로

		lblSelectNic = new JLabel("NIC List");
		lblSelectNic.setBounds(383, 38, 170, 20);
		pane.add(lblSelectNic);//

		lblsrc = new JLabel("Source Mac Address");
		lblsrc.setBounds(383, 123, 170, 20);
		pane.add(lblsrc);

		lbldst = new JLabel("Destination IP Address");
		lbldst.setBounds(383, 182, 170, 20);
		pane.add(lbldst);

		Setting_Button = new JButton("Setting");// setting
		Setting_Button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {

				if (Setting_Button.getText() == "Reset") {
					srcMacAddress.setText("");
					dstMacAddress.setText("");
					Setting_Button.setText("Setting");
					dstMacAddress.setEditable(true);
				} else {
					byte[] srcAddress = new byte[6];
					byte[] dstAddress = new byte[6];

					String src = srcMacAddress.getText();
					String dst = dstMacAddress.getText();

					String[] byte_src = src.split("-");
					for (int i = 0; i < 6; i++) {
						srcAddress[i] = (byte) Integer.parseInt(byte_src[i], 16);
					}

					String[] byte_dst = dst.split("\\."); // IP address입력을 위한 split
					for (int i = 0; i < 4; i++) {
						dstAddress[i] = (byte) Integer.parseInt(byte_dst[i], 16);
					}

//					((EthernetLayer) m_LayerMgr.GetLayer("Ethernet")).SetEnetSrcAddress(srcAddress);
//					((EthernetLayer) m_LayerMgr.GetLayer("Ethernet")).SetEnetDstAddress(dstAddress);

					((NILayer) m_LayerMgr.GetLayer("NI")).SetAdapterNumber(selected_index);

					Setting_Button.setText("Reset");
					dstMacAddress.setEditable(false);

					try {
						myIPAddress = InetAddress.getLocalHost();
					} catch (UnknownHostException e) {
						e.printStackTrace();
					}
					System.out.println("IP of my system is := " + myIPAddress.getHostAddress()); // Just for debugging
					ChattingArea.append("IP of my system is := " + myIPAddress.getHostAddress() + "\n"); // Show host
																											// IP.

				}

			}
		});
		Setting_Button.setBounds(418, 243, 87, 20);
		pane.add(Setting_Button);// setting

		File_select_Button = new JButton("File select");// 파일 선택
		File_select_Button.addActionListener(new ActionListener() {

			public void actionPerformed(ActionEvent arg0) {
				if (Setting_Button.getText() == "Reset") {

					fd = new FileDialog(ChatFileDlg.this, "파일선택", FileDialog.LOAD);
					fd.setVisible(true);

					if (fd.getFile() != null) {
						path = fd.getDirectory() + fd.getFile();
						FileDir_path.setText("" + path);
					}
				} else {
					JOptionPane.showMessageDialog(null, "주소 설정 오류", "WARNING_MESSAGE", JOptionPane.WARNING_MESSAGE);
				}
			}
		});
		File_select_Button.setBounds(75, 336, 161, 21);// 파일 선택
		pane.add(File_select_Button);

		Chat_send_Button = new JButton("Send");
		Chat_send_Button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				if (Setting_Button.getText() == "Reset") {
					String input = ChattingWrite.getText();

					ChattingArea.append("[SEND] : " + input + "\n");

					byte[] type = new byte[2];
					type[0] = 0x08;
					type[1] = 0x20;
					// ((EthernetLayer) m_LayerMgr.GetLayer("Ethernet")).SetEnetType(type);

					byte[] bytes = input.getBytes();
					m_LayerMgr.GetLayer("Chat").Send(bytes, bytes.length);
					// p_UnderLayer.Send(bytes, bytes.length);
				} else {
					JOptionPane.showMessageDialog(null, "주소 설정 오류");
				}
			}
		});
		Chat_send_Button.setBounds(383, 274, 161, 21);
		pane.add(Chat_send_Button);

		NIC_select_Button = new JButton("Select");
		NIC_select_Button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				String selected = comboBox.getSelectedItem().toString();
				selected_index = comboBox.getSelectedIndex();
				srcMacAddress.setText("");
				try {
					byte[] MacAddress = ((NILayer) m_LayerMgr.GetLayer("NI")).GetAdapterObject(selected_index)
							.getHardwareAddress();
//					for(int i=0; i<6; ++i)	//	for debugging
//						System.out.println(MacAddress[i]);
					String hexNumber;
					for (int i = 0; i < 6; i++) {
						hexNumber = Integer.toHexString(0xff & MacAddress[i]);
						srcMacAddress.append(hexNumber.toUpperCase());
						if (i != 5)
							srcMacAddress.append("-");
					}
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		});

		NIC_select_Button.setBounds(418, 94, 87, 23);
		pane.add(NIC_select_Button);

		File_send_Button = new JButton("File Send");
		File_send_Button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				if (Setting_Button.getText() == "Reset") {
					byte[] type = new byte[2];
					type[0] = 0x08;
					type[1] = 0x30;
//					((EthernetLayer) m_LayerMgr.GetLayer("Ethernet")).SetEnetType(type);

					String filepath = FileDir_path.getText();
					System.out.println(filepath);
					m_LayerMgr.GetLayer("File").Send(filepath);
					// p_UnderLayer.Send(filename);
				}

				else {
					JOptionPane.showMessageDialog(null, "주소 설정 오류");
				}
			}
		});
		File_send_Button.setBounds(322, 336, 161, 23);
		pane.add(File_send_Button);

		comboBox = new JComboBox();

		comboBox.setBounds(380, 63, 170, 24);
		pane.add(comboBox);
		// 내가 추가한 부분들~~

		hwAddress = new JTextField();
		hwAddress.setColumns(10);
		hwAddress.setBounds(125, 446, 400, 24);
		pane.add(hwAddress);

		lblhw = new JLabel("HW Address");
		lblhw.setBounds(43, 446, 80, 24);
		pane.add(lblhw);

		HwAddress_send_Button = new JButton("HW Send");
		HwAddress_send_Button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String pattern = "[0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0 -9a-fA-F]{2}[-:][0-9a-fA-F]{2}";	// MAC address pattern
				String inputMAC = hwAddress.getText();

				if (Pattern.matches(pattern, inputMAC)) { // If inputed MAC is valid pattern, continue

					byte[] bytes = new byte[6];

					String[] macString = inputMAC.split("\\-"); // Split the string array by "\\-"
					for (int i = 0; i < 6; i++) {
						bytes[i] = (byte) Integer.parseInt(macString[i], 16); // Cast the integers to byte
//					System.out.println(bytes[i]);	//	for debugging
					}

//					-2 : GARP
					m_LayerMgr.GetLayer("TCP").Send(bytes, -2); // Explicitly send -2 instead of bytes.length

				} else {
					JOptionPane.showMessageDialog(null, "유효하지 않은 MAC 주소");
				}
			}
		});
		HwAddress_send_Button.setBounds(199, 486, 161, 21);
		pane.add(HwAddress_send_Button);

		JPanel paneG = new JPanel();
		paneG.setBorder(new TitledBorder(null, "Gratuitous ARP", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		paneG.setBounds(12, 390, 550, 136);
		pane.add(paneG);

		JButton Item_Delete_Button = new JButton("Item Delete");
		Item_Delete_Button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (Table_ARP_Cache.getSelectedRow() == -1) { // getSelectedRow() returns -1 if no row is selected.
					return;
				} else { // else, getSelectedRow() returns the index of the first selected row.
					dtm_ARP.removeRow(Table_ARP_Cache.getSelectedRow()); // Delete the selected row.
				}

			}
		});
		Item_Delete_Button.setBounds(587, 442, 161, 21);
		pane.add(Item_Delete_Button);

		JButton All_Delete_Button = new JButton("All Delete");
		All_Delete_Button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {

				dtm_ARP.setRowCount(0); // setRowCount(0) makes the DefaultTableModel (dfm_ARP) erase all the rows.

			}
		});
		All_Delete_Button.setBounds(760, 442, 161, 21);
		pane.add(All_Delete_Button);

		JLabel lblIpaddr = new JLabel("IP_Addr");
		lblIpaddr.setBounds(580, 487, 49, 20);
		pane.add(lblIpaddr);

		ARPIpAddress = new JTextField();
		ARPIpAddress.setColumns(10);
		ARPIpAddress.setBounds(637, 487, 183, 20);
		pane.add(ARPIpAddress);

		JButton ARP_Send_Button = new JButton("Send");
		ARP_Send_Button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String pattern = "((\\d|[1-9]\\d|1\\d\\d|2[0-4]\\d|25[0-5])([.](?!$)|$)){4}"; // IP address pattern
				String inputIP = ARPIpAddress.getText();
				String defaultMAC = "????????????";
				String isComplete = "incomplete";

				if (Pattern.matches(pattern, inputIP)) { // If inputed IP is valid pattern, continue
					String inputString[] = new String[3]; // Set a string array for the row to be inputed.
					inputString[0] = inputIP;
					inputString[1] = defaultMAC;
					inputString[2] = isComplete;

					dtm_ARP.addRow(inputString); // Add a row with inputIP + default MAC, Completeness values.

					byte[] bytes = new byte[4];

					String[] ipString = inputIP.split("\\."); // Split the string array by "\\."
					for (int i = 0; i < 4; i++) {
						bytes[i] = (byte) Integer.parseInt(ipString[i], 16); // Cast the integers to byte
					}

					//	-1 : ARP
					m_LayerMgr.GetLayer("TCP").Send(bytes, -1); // Explicitly send -1 instead of bytes.length
				} else {
					JOptionPane.showMessageDialog(null, "유효하지 않은 IP 주소");
				}

				ARPIpAddress.setText("");
			}
		});
		ARP_Send_Button.setBounds(832, 486, 97, 21);
		pane.add(ARP_Send_Button);

		lblIpaddr_2 = new JLabel("IP_\uC8FC\uC18C");
		lblIpaddr_2.setBounds(1009, 397, 58, 20);
		pane.add(lblIpaddr_2);

		PARPIpAddress = new JTextField();
		PARPIpAddress.setColumns(10);
		PARPIpAddress.setBounds(1079, 397, 183, 20);
		pane.add(PARPIpAddress);

		lblIpaddr_3 = new JLabel("MAC_\uC8FC\uC18C");
		lblIpaddr_3.setBounds(1009, 440, 58, 20);
		pane.add(lblIpaddr_3);

		PARPMacAddress = new JTextField();
		PARPMacAddress.setColumns(10);
		PARPMacAddress.setBounds(1079, 440, 183, 20);
		pane.add(PARPMacAddress);

		Proxy_Entry_Add_Button = new JButton("Add");
		Proxy_Entry_Add_Button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				// Add data to PARP Entry
				String inputDevice = PARPDevice.getText();
				String inputIP = PARPIpAddress.getText();
				String inputMAC = PARPMacAddress.getText();

				String inputString[] = new String[3]; // Set a string array for the row to be inputed.
				inputString[0] = inputDevice;
				inputString[1] = inputIP;
				inputString[2] = inputMAC;

				dtm_PARP.addRow(inputString); // Add a row with inputDevice + inputIP + inputMAC values.

				PARPDevice.setText("");
				PARPIpAddress.setText("");
				PARPMacAddress.setText("");
			}
		});
		Proxy_Entry_Add_Button.setBounds(968, 486, 161, 21);
		pane.add(Proxy_Entry_Add_Button);

		Proxy_Entry_Delete_Button = new JButton("Delete");
		Proxy_Entry_Delete_Button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (Table_PARP_Entry.getSelectedRow() == -1) { // getSelectedRow() returns -1 if no row is selected.
					return;
				} else { // else, getSelectedRow() returns the index of the first selected row.
					dtm_PARP.removeRow(Table_PARP_Entry.getSelectedRow()); // Delete the selected row.
				}
			}
		});
		Proxy_Entry_Delete_Button.setBounds(1141, 486, 161, 21);
		pane.add(Proxy_Entry_Delete_Button);

		panel_2 = new JPanel();
		panel_2.setBorder(new TitledBorder(
				new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)),
				"Chat & File Transfer", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		panel_2.setBounds(12, 13, 550, 358);
		pane.add(panel_2);

		JPanel panel = new JPanel();
		panel.setBorder(new TitledBorder(null, "ARP Cache", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		panel.setBounds(565, 13, 379, 513);
		pane.add(panel);

		panel_1 = new JPanel();
		panel_1.setBorder(new TitledBorder(
				new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)),
				"Proxy ARP Entry", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		panel_1.setBounds(948, 13, 375, 513);
		pane.add(panel_1);

		setVisible(true);

		SetCombobox();
	}

	private void SetCombobox() {
		List<PcapIf> m_pAdapterList = new ArrayList<PcapIf>();
		StringBuilder errbuf = new StringBuilder();

		int r = Pcap.findAllDevs(m_pAdapterList, errbuf);
		if (r == Pcap.NOT_OK || m_pAdapterList.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
			return;
		}
		for (int i = 0; i < m_pAdapterList.size(); i++)
			this.comboBox.addItem(m_pAdapterList.get(i).getDescription());
	}

	public boolean Receive(byte[] input) {
		byte[] data = input;
		String Text = new String(data);
		ChattingArea.append("[RECV] : " + Text + "\n");
		return false;
	}

	@Override
	public void SetUnderLayer(BaseLayer pUnderLayer) {
		// TODO Auto-generated method stub
		if (pUnderLayer == null)
			return;
		this.p_UnderLayer = pUnderLayer;
	}

	@Override
	public void SetUpperLayer(BaseLayer pUpperLayer) {
		// TODO Auto-generated method stub
		if (pUpperLayer == null)
			return;
		this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);
		// nUpperLayerCount++;
	}

	@Override
	public String GetLayerName() {
		// TODO Auto-generated method stub
		return pLayerName;
	}

	@Override
	public BaseLayer GetUnderLayer() {
		// TODO Auto-generated method stub
		if (p_UnderLayer == null)
			return null;
		return p_UnderLayer;
	}

	@Override
	public BaseLayer GetUpperLayer(int nindex) {
		// TODO Auto-generated method stub
		if (nindex < 0 || nindex > nUpperLayerCount || nUpperLayerCount < 0)
			return null;
		return p_aUpperLayer.get(nindex);
	}

	@Override
	public void SetUpperUnderLayer(BaseLayer pUULayer) {
		this.SetUpperLayer(pUULayer);
		pUULayer.SetUnderLayer(this);

	}

	public InetAddress getMyIPAddress() {
		return myIPAddress;
	}

	public void setMyIPAddress(InetAddress myIPAddress) {
		this.myIPAddress = myIPAddress;
	}
}
