package triematch;

import java.util.ArrayList;

/**
 *
 * @author Thinkpad
 */
public class Node {

    private ArrayList<Node> nodesBelow = new ArrayList<Node>();
    private int step = 1;
    private String value;
    public static int numberOfLookup=0;

    public Node(int step) {
        this.step = step;
    }

    public void build(String dataString) {
        if (dataString.length() > 0) {
            //System.out.println("Node: " + this.toString() + " - Info to parse: " + dataString);
            value = dataString.substring(0, Math.min(step, dataString.length()));
            //System.out.println("Node: " + this.toString() + " - My values is/are: " + value);
            dataString = dataString.substring(Math.min(step, dataString.length()), dataString.length());
            //System.out.println(" The remainig data is: " + dataString);

            if (dataString.length() != 0) {
                if (nodesBelow.size() == 0) { //It's a new node down
                    Node newNode = new Node(step);
                    newNode.build(dataString);
                    nodesBelow.add(newNode);
                } else { //I have already some node down

                    Boolean isThere = false;
                    for (Node node : nodesBelow) {
                        if (node.getValue().compareTo(dataString.substring(0, Math.min(step, dataString.length()))) == 0) {
                            //System.out.println("Node: " + this.toString() + " - I have already this node");
                            if(node.getTreeSize()!=0){
                                node.build(dataString); //Let's continue the build
                                isThere = true;
                            }else{
                                //System.out.println("Node: " + this.toString() + " - The tree is short and i'm stopping here\n");
                                return;
                            }
                        }
                    }

                    if (isThere == false) {
                        Node newNode = new Node(step);
                        newNode.build(dataString);
                        nodesBelow.add(newNode);
                    }
                }
            } else {
                //System.out.println("Node: " + this.toString() + " - Parsing ended and killed all the bottom\n");
                nodesBelow = new ArrayList<Node>();
            }
        } else {
            System.out.println("Parsing ended 2, there is an error!!");
        }
    }

    public void buildMain(String dataString) {
        if (dataString.length() > 0) {
            //System.out.println("Node: " + this.toString() + " - Info to parse main: " + dataString);

            //Optimization
            for (Node node : nodesBelow) {
                if (node.getValue().compareTo(dataString.substring(0, Math.min(step, dataString.length()))) != 0 && node.getValue().startsWith(dataString.substring(0, Math.min(step, dataString.length())))) {
                    //System.out.println("Node: " + this.toString() + " - I have optimized the tree by chopping away "+node.toString()+" a long part");
                    nodesBelow.remove(node);


                    Node newNode = new Node(step);
                    newNode.build(dataString.substring(0, Math.min(step, dataString.length())));
                    nodesBelow.add(newNode);
                    return; //The new value is short hence i don't need this entire line
                } else if (node.getValue().length() < step && dataString.substring(0, Math.min(step, dataString.length())).startsWith(node.getValue())) {
                    //System.out.println("Node: " + this.toString() + " - The value \""+node.getValue()+"\" that is stored in one of my node is smaller so it will kill this entire new line\n");
                    return; //The value is already sotred is short hence is killing all ip later
                }else if ( node.getValue().length()== step && node.getTreeSize() ==0 && dataString.length()>step && dataString.startsWith(node.getValue()) ){
                    //System.out.println("Node: " + this.toString() + " - The value \""+node.getValue()+"\" that is stored in one of my node is smaller complete so it will kill this entire new line\n");
                    return; //The value is already sotred is short hence is killing all ip later
                }
            }

            if (dataString.length() != 0) {
                if (nodesBelow.size() == 0) { //It's a new node down
                    Node newNode = new Node(step);
                    newNode.build(dataString);
                    nodesBelow.add(newNode);
                } else { //I have already some node down

                    Boolean isThere = false;
                    for (Node node : nodesBelow) {
                        if (node.getValue().compareTo(dataString.substring(0, Math.min(step, dataString.length()))) == 0) {
                            //System.out.println("Node: " + this.toString() + " - I have already this node");
                            node.build(dataString); //Let's continue the build
                            isThere = true;
                        }
                    }

                    if (isThere == false) {
                        Node newNode = new Node(step);
                        newNode.build(dataString);
                        nodesBelow.add(newNode);
                    }
                }
            } else {
                //System.out.println("Node: " + this.toString() + " - Parsing ended \n");
            }
        } else {
            System.out.println("Parsing ended 2, there is an error!!");
        }
    }

    public boolean check(String dataString) {
        numberOfLookup ++;
        for (Node node : nodesBelow) {
            if (node.getValue().compareTo(dataString.substring(0, Math.min(step, dataString.length()))) == 0) {
                    return node.check(dataString.substring(Math.min(step, dataString.length()), dataString.length()));
            }               
        }
        
        if(nodesBelow.size()==0){
            return true;
        }
        
        return false;
    }

    public String getValue() {
        return value;
    }
    
    public int getTreeSize(){
        return nodesBelow.size();
    }

}
