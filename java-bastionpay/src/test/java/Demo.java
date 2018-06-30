import com.bastion.gateway.api.BostainApiUtil;
import org.junit.Test;

import java.util.List;

public class Demo {

    @Test
    public  void ceateAddress(){
        try {
            List<String> result = BostainApiUtil.createAddress("BTC", 1);
            System.out.println(result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
