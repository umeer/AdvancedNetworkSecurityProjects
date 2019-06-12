/*
 * Develped by Umeer Mohammad St.N.:4748549
 *
 */
package triematch;

import java.util.concurrent.ThreadLocalRandom;
import java.util.ArrayList;


/*
Using java I built a tree generator based on dynamic class recursion. 
The program firstly read the data from a file (same data as the given website) and then it creates a tree, lastly, the program tests the lookup of random IPs and the output is given on console and it consists of duration time and number of lookups 
The program has multiple configuration parameters:
•	FILE_BLOCKED_IP =  location of the blocked IP file
•	TOTAL_BLOCKED_IP = number of IP among the latter file that the program has to actually store in the tree, if equal to -1 it build the tree with all the IPS in the list.
•	WIDTH_OF_TREE = this number indicates the structure of the tree, if equal to 1 it's a single but trie and if equal to 2 the program will build a 2-stride multi-bit trie, it is however possible to set any positive integer number.
•	NUMBER_OR_READING_TEST = The output is based on an average on multiple random reading, this value indicates how many reading the program need to do.
*/

public class TrieMatch {

    public static void main(String[] args) {
        String FILE_BLOCKED_IP = "data.txt";
        int TOTAL_BLOCKED_IP = -1; //if negative it will block all the ip in the file, if positive it indicated the number of ip blocked
        int WIDTH_OF_TREE = 2; // this number indicate the number of element stored in a node, for the assagament is 1 or 2
        int NUMBER_OR_READING_TEST = 1000; //How many reading i have to use for the average calculation?

        
        System.out.println("Umeer Mohammad St.N.:4748549");
        
        //Loading data
        FileReader file = new FileReader(FILE_BLOCKED_IP);
        ArrayList<IpAddress> listIp = file.getListIp(TOTAL_BLOCKED_IP);

        //Database loading
        Node tree = new Node(WIDTH_OF_TREE);
        for (IpAddress ipAddress : listIp) {
            tree.buildMain(ipAddress.addressBinary);
        }

        System.out.println("\n\n\n\n");

        //Reading        
        long lStartTime, lEndTime, diffTime, avgDiffTime = 0;
        int random, avgNumberOfHops = 0;

        for (int i = 0; i < NUMBER_OR_READING_TEST; i++) {
            Node.numberOfLookup = 0;
            lStartTime = System.nanoTime();
            random = ThreadLocalRandom.current().nextInt(0, listIp.size());
            System.out.print("Result:" + tree.check(listIp.get(random).addressBinary));
            lEndTime = System.nanoTime();
            diffTime = lEndTime - lStartTime;
            System.out.println(" Lookup Time: " + diffTime / 1000 + " us Number Lookup: " + Node.numberOfLookup);
            avgDiffTime = avgDiffTime + diffTime;
            avgNumberOfHops = avgNumberOfHops + Node.numberOfLookup;
        }
        System.out.println(" [Average] Lookup Time: " + (avgDiffTime / NUMBER_OR_READING_TEST) / 1000 + " us and Number of Lookup: " + avgNumberOfHops / NUMBER_OR_READING_TEST);

    }
}
