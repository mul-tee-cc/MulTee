package cc.multee.impl;

import cc.multee.MulTeeException;

import java.util.Queue;
import java.util.LinkedList;
import java.util.Arrays;


public class Util {

    private static void usage( Queue<String> args, String msg ) {
        if( args.isEmpty() || "-h".equals(args.peek()) ) {
            System.out.println(msg);
            System.exit(1);
        }
    }

    public static void main(String[] args) {

        Queue<String> argz = new LinkedList<>(Arrays.asList(args));

        usage( argz, "java -jar multee-java.jar [-h|tofu]" );

        switch( argz.remove() ) {

            case "tofu": {
                usage(argz, "java -jar multee-java.jar tofu <csrZipFile> <comma-separated-SN>");

                String csrZipFile = argz.remove();
                String SN = argz.remove();

                MulTeeImpl multee = MulTeeImpl.dummyFactory();

                MulTeeException.unwrap(multee.generateCSR(csrZipFile,SN));

                break;
            }
        }
    }
}
