package chat_file;

import java.awt.Container;
import java.awt.FileDialog;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.sound.sampled.AudioFormat.Encoding;
import javax.swing.*;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import javax.swing.border.TitledBorder;
import javax.swing.border.EtchedBorder;
import java.awt.Color;

public class ChatFileDlg extends JFrame implements BaseLayer {
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();

	String path;

	private static LayerManager m_LayerMgr = new LayerManager();
	int selected_index;
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
	private JTextArea ChattingArea_Proxy_ARP_Entry;
	private JLabel lblIpaddr_1;
	private JTextField PARPDevice;
	private JLabel lblIpaddr_2;
	private JTextField PARPIpAddress;
	private JLabel lblIpaddr_3;
	private JTextField PARPMacAddress;
	private JButton Proxy_Entry_Add_Button;
	private JButton Proxy_Entry_Delete_Button;
	private JPanel panel_2;

	public static void main(String[] args) {
		m_LayerMgr.AddLayer(new NILayer("NI"));
		
		m_LayerMgr.AddLayer(new ChatFileDlg("GUI"));

		//m_LayerMgr.ConnectLayers( );
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
		srcMacAddress.setEditable(false);
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
		pane.add(lblSelectNic);// 글자

		lblsrc = new JLabel("Source Mac Address");
		lblsrc.setBounds(383, 123, 170, 20);
		pane.add(lblsrc);

		lbldst = new JLabel("Destination Mac Address");
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

					String[] byte_dst = dst.split("-");
					for (int i = 0; i < 6; i++) {
						dstAddress[i] = (byte) Integer.parseInt(byte_dst[i], 16);
					}

//					((EthernetLayer) m_LayerMgr.GetLayer("Ethernet")).SetEnetSrcAddress(srcAddress);
//					((EthernetLayer) m_LayerMgr.GetLayer("Ethernet")).SetEnetDstAddress(dstAddress);

					((NILayer) m_LayerMgr.GetLayer("NI")).SetAdapterNumber(selected_index);

					Setting_Button.setText("Reset");
					dstMacAddress.setEditable(false);
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
		File_select_Button.setBounds(75, 336, 161, 21);// 파일 선택위치 280
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
					//((EthernetLayer) m_LayerMgr.GetLayer("Ethernet")).SetEnetType(type);

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
		//내가 추가한 부분들~~~~~~~~~~~
		
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
			}
		});
		HwAddress_send_Button.setBounds(199, 486, 161, 21);
		pane.add(HwAddress_send_Button);
		
		JPanel paneG = new JPanel();
		paneG.setBorder(new TitledBorder(null, "Gratuitous ARP", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		paneG.setBounds(12, 390, 550, 136);
		pane.add(paneG);
		
		//내가 추가한 부분들~~~~~~~~~~~
		
		JTextArea ChattingArea_ARP_Cache = new JTextArea();
		ChattingArea_ARP_Cache.setEditable(false);
		ChattingArea_ARP_Cache.setBounds(577, 38, 352, 386);
		pane.add(ChattingArea_ARP_Cache);
		
		JButton Item_Delete_Button = new JButton("Item Delete");
		Item_Delete_Button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
			}
		});
		Item_Delete_Button.setBounds(587, 442, 161, 21);
		pane.add(Item_Delete_Button);
		
		JButton All_Delete_Button = new JButton("All Delete");
		All_Delete_Button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
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
		ARP_Send_Button.setBounds(832, 486, 97, 21);
		pane.add(ARP_Send_Button);
		
		JPanel panel = new JPanel();
		panel.setBorder(new TitledBorder(null, "ARP Cache", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		panel.setBounds(565, 13, 379, 513);
		pane.add(panel);
		
		ChattingArea_Proxy_ARP_Entry = new JTextArea();
		ChattingArea_Proxy_ARP_Entry.setEditable(false);
		ChattingArea_Proxy_ARP_Entry.setBounds(958, 38, 352, 287);
		pane.add(ChattingArea_Proxy_ARP_Entry);
		
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
		Proxy_Entry_Add_Button.setBounds(968, 486, 161, 21);
		pane.add(Proxy_Entry_Add_Button);
		
		Proxy_Entry_Delete_Button = new JButton("Delete");
		Proxy_Entry_Delete_Button.setBounds(1141, 486, 161, 21);
		pane.add(Proxy_Entry_Delete_Button);
		
		panel_2 = new JPanel();
		panel_2.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "Chat & File Transfer", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		panel_2.setBounds(12, 13, 550, 358);
		pane.add(panel_2);
		
		panel_1 = new JPanel();
		panel_1.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "Proxy ARP Entry", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
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
}

