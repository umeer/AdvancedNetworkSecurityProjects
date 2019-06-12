package triematch;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Thinkpad
 */
public class FileReader {

    private String fileName;
    private ArrayList<IpAddress> listIp = new ArrayList<IpAddress>();

    public FileReader(String fileName) {
        this.fileName = fileName;
        readFile();
    }

    private void readFile() {

        try {
            Path path = FileSystems.getDefault().getPath(fileName);
            List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
            parseData(lines);
        } catch (IOException ex) {
            Logger.getLogger(FileReader.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void parseData(List<String> lines) {
        for (String line : lines) {

            try {
                String ip = line.substring(0, line.indexOf("/"));
                String mask = (line.substring(line.indexOf("/") + 1, line.indexOf("/") + 3)).replace("\t", "");
                listIp.add(new IpAddress(ip, Integer.parseInt(mask)));
                //System.out.println(ip + "  " + mask);
            } catch (Exception e) {
                System.out.println("Data parsing failed: " + line.substring(0, line.indexOf("/")) + "  #" + line.substring(line.indexOf("/") + 1, line.indexOf("/") + 3) + "#");
            }

        }

        if (listIp.size() > 0) {
            conversionData();
        }
    }

    private void conversionData() {
        for (IpAddress ipAddress : listIp) {
            ipAddress.addressBinary = IpAddress.binaryConversion(ipAddress.address).subSequence(0, ipAddress.subnet) + "";
        }
    }

    public ArrayList<IpAddress> getListIp(int quantity) {

        if (quantity < 0) {
            return listIp;
        } else {

            ArrayList<IpAddress> returnItem = new ArrayList<IpAddress>();
            for (IpAddress ipAddress : listIp) {
                returnItem.add(ipAddress);
                quantity--;
                if (quantity < 1) {
                    break;
                }

            }

            return returnItem;
        }
    }
}

class IpAddress {

    public String address;
    public String addressBinary;
    public int subnet;

    public IpAddress(String address, int subnet) {
        this.address = address;
        this.subnet = subnet;
    }

    public static String binaryConversion(final String ip) {
        int len = ip.length();
        int addr = 0;
        int fullAddr = 0;
        char[] out = new char[32];

        // Parse the four segments of the IP address.
        for (int i = 0; i < len; i++) {
            char digit = ip.charAt(i);
            if (digit != '.') {
                addr = addr * 10 + (digit - '0');
            } else {
                fullAddr = (fullAddr << 8) | addr;
                addr = 0;
            }
        }
        fullAddr = (fullAddr << 8) | addr;

        // At this point, fullAddr holds the IP address as a 32-bit integer.
        for (int i = 0; i < 32; i++, fullAddr <<= 1) {
            out[i] = ((fullAddr & 0x80000000) != 0) ? '1' : '0';
        }
        return new String(out);
    }

}
