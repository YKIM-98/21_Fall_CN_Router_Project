package arp;

import java.util.*;

public class ARPLayer implements BaseLayer{
    public int nUpperLayerCount = 0;
    public BaseLayer p_UnderLayer = null;    
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();    
	public String pLayerName = null;
	
	public ARPLayer(String name){
		this.pLayerName = name;
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
        this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);// layer異붽�
	}

	@Override
	public void SetUpperUnderLayer(BaseLayer pUULayer) {
        this.SetUpperLayer(pUULayer);
        pUULayer.SetUnderLayer(this);
	}

	public static boolean containMacAddress(byte[] addr) {
		// TODO Auto-generated method stub
		return false;
	}

}
