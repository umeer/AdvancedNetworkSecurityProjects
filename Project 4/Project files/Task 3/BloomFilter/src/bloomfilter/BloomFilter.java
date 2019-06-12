/*
 * Develped by Umeer Mohammad St.N.:4748549
 * Library Used : https://github.com/OpenHFT/Zero-Allocation-Hashing
 *
 */
package bloomfilter;

import java.util.BitSet;
import net.openhft.hashing.LongHashFunction;
/*

To test the performance of the Boom Filter I created a small program with java able to simulate the filter. The result of the test where very interesting, due to the way of how the filter works there is no performance degradation associated with number IP address stored, hence the timing for all the tests were similar. The performance of filtration is amazing, just 25 microseconds (AVG) per IP lookup.

*/

public class BloomFilter {

    public static void main(String[] args) {

        int M = 175000000; //Dimension of the bloom filter
        int K = 30; //Number of different hash functions
        long MAX_SIZE = 2000000; //Max number of Ip that will be stored (from 0 to 2M with step of 100'000)
        int NUMBER_OR_READING_TEST = 100; //Number of reading before calulate the average (stay less the 255 because it is used also to buid the ip)
        long lStartTime, lEndTime, diffTime;
        int one = 0, two = 0, three = 0;

        System.out.println("Umeer Mohammad St.N.:4748549");

        //Database creation
        BitSet bitset = new BitSet(M);
        lStartTime = System.nanoTime();
        for (long i = 0; i < MAX_SIZE; i++) {
            for (int seed = 0; seed < K; seed++) {
                bitset.set(Math.toIntExact(Math.abs(LongHashFunction.xx(seed).hashChars("1." + one + "." + two + "." + three)) % M));
            }
            three++;
            if (three > 255) {
                two++;
                three = 0;
                if (two > 255) {
                    one++;
                    two = 0;
                }
            }
        }
        lEndTime = System.nanoTime();
        diffTime = lEndTime - lStartTime;
        System.out.println("Initializzation Time: " + diffTime / 1000000 + " ms");

        
        
        
        
        //Fetch system
        long avgTime = 0;
        for (int j = 0; j < NUMBER_OR_READING_TEST; j++) {
            String ipToFind = "1.1.1." + j;
            int counterFound = 0;

            lStartTime = System.nanoTime();

            for (int seed = 0; seed < K; seed++) {
                if (bitset.get(Math.toIntExact(Math.abs(LongHashFunction.xx(seed).hashChars(ipToFind)) % M))) {
                    counterFound++;
                }
            }

//             if(counterFound == K){
//                System.out.println("Ip: "+ ipToFind + " found");
//             }else{
//                System.out.println("Ip: "+ ipToFind + " not found K= "+counterFound);
//             }
            lEndTime = System.nanoTime();
            diffTime = lEndTime - lStartTime;
            System.out.println("Search Time: " + diffTime / 1000 + " us");
            avgTime = avgTime + diffTime;
        }

        System.out.println("Search AVG Time: " + avgTime / NUMBER_OR_READING_TEST / 1000 + " us");

    }
}
