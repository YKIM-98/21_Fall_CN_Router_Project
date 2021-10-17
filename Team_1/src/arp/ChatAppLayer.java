package arp;

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

    private byte[] totalLength(int lengthOfStr) {
        byte[] totalLength = new byte[2];
        totalLength[0] = (byte) ((lengthOfStr & 0xFF00) >> 8);
        totalLength[1] = (byte) (lengthOfStr & 0xFF);
        return totalLength;
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
	
    private byte[] objectToByte(byte[] input, int length, byte[] totlen, byte type) {
        byte[] sendData = new byte[length + 4];
        sendData[0] = totlen[0];
        sendData[1] = totlen[1];
        sendData[2] = type;
        sendData[3] = 0x00;

        if (length >= 0) {
            System.arraycopy(input, 0, sendData, 4, length);
        }

        return sendData;
    }
	
    public boolean Send(byte[] input, int length) {     	 
        byte[] totalLength = this.totalLength(length);	// char context length
        byte type = 0x00;
        byte[] sendData = this.objectToByte(input, length, totalLength, type);
        /* sendData 
         * 0~1 : context length
         * 2 : type (chat - 0)
         * 3 : unused
         * 4~1456 : data
        */
        return this.GetUnderLayer().Send(sendData, sendData.length);
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
		return pLayerName;
	}

	@Override
	public BaseLayer GetUnderLayer() {
        if (p_UnderLayer == null)
            return null;
        return p_UnderLayer;
	}

	@Override
	public BaseLayer GetUpperLayer(int nindex) {
        if (nindex < 0 || nindex > nUpperLayerCount || nUpperLayerCount < 0)
            return null;
        return p_aUpperLayer.get(nindex);
	}

	@Override
	public void SetUnderLayer(BaseLayer pUnderLayer) {
        if (pUnderLayer == null)
            return;
        this.p_UnderLayer = pUnderLayer;
	}

	@Override
	public void SetUpperLayer(BaseLayer pUpperLayer) {
        if (pUpperLayer == null)
            return;
        this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);//layer추가	
	}

	@Override
	public void SetUpperUnderLayer(BaseLayer pUULayer) {
        this.SetUpperLayer(pUULayer);
        pUULayer.SetUnderLayer(this);			
	}

}
