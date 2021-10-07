package chat_file;

import java.util.ArrayList;

public class ChatAppLayer implements BaseLayer{
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
	
	private class _CAPP_HEADER{
		byte[] capp_totlen;
		byte capp_type;
		byte capp_unused;
		byte[] capp_data;
		
		public _CAPP_HEADER(){
			this.capp_totlen = new byte[2];
			this.capp_type = 0x00;
			this.capp_unused = 0x00;
			this.capp_data = null;
		}
	}
	
	_CAPP_HEADER m_sHeader = new _CAPP_HEADER();
	
	public ChatAppLayer(String pName) {
		//super(pName);
		// TODO Auto-generated constructor stub
		pLayerName = pName;
		ResetHeader();
	}
	
	public void ResetHeader(){
		for(int i=0; i<2; i++){
			m_sHeader.capp_totlen[i] = (byte) 0x00;
		}
		m_sHeader.capp_type = (byte) 0x00;	
		m_sHeader.capp_unused = (byte) 0x00;	
		m_sHeader.capp_data = null;	
	}
	
	public byte[] ObjToByte(_CAPP_HEADER Header, byte[] input, int length){
	
		return null;		
	}
	
    public boolean Send(byte[] input, int length) {     	 
    	
		return false;
	}
//    
//    public byte[] RemoveCappHeader(byte[] input, int length){
//    
//    }
           
	public boolean Receive(byte[] input){
	
		return true;
	}

	@Override
	public String GetLayerName() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public BaseLayer GetUnderLayer() {
		return null;
	}

	@Override
	public BaseLayer GetUpperLayer(int nindex) {
		return null;
	}

	@Override
	public void SetUnderLayer(BaseLayer pUnderLayer) {

	}

	@Override
	public void SetUpperLayer(BaseLayer pUpperLayer) {
	
	}

	@Override
	public void SetUpperUnderLayer(BaseLayer pUULayer) {
			
	}

}
