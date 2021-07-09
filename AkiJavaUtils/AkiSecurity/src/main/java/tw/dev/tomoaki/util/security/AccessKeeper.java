/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package tw.dev.tomoaki.util.security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @author tomoaki
 */
public class AccessKeeper {

    public enum Method {
        NoHead(1, "去頭", "編碼後去頭"),
        NoTail(2, "去尾", "編碼後去尾"),
        NoHeadAndNoTail(3, "去頭去尾", "編碼後去頭去尾");

        private Integer code;
        private String summary;
        private String detail;

        private Method(Integer code, String summary, String detail) {
            this.code = code;
            this.summary = summary;
            this.detail = detail;
        }

        public Integer getCode() {
            return code;
        }

        public void setCode(Integer code) {
            this.code = code;
        }

        public String getSummary() {
            return summary;
        }

        public void setSummary(String summary) {
            this.summary = summary;
        }

        public String getDetail() {
            return detail;
        }

        public void setDetail(String detail) {
            this.detail = detail;
        }

        public static Method codeOf(Integer designatedCode) {
            Method designatedMethod = null;
            for (Method method : Method.values()) {
                if (method.getCode().equals(designatedCode)) {
                    designatedMethod = method;
                    break;
                }
            }
            if (designatedMethod == null) {
                throw new IllegalArgumentException("Cannot found[" + designatedCode + "]");
            }
            return designatedMethod;
        }

    }

    private final String prefixPk = "toMoaki";
    private final String suffixPk = "AccESsKeEPer";
    private final String middlePk = "KuROsAki";
    private String theAlgorithm;
    private MessageDigest md;
    private Boolean debugMode;

    protected AccessKeeper() {
    }

    public static class Factory {

        public static AccessKeeper create() throws NoSuchAlgorithmException {
            AccessKeeper keeper = new AccessKeeper();
            keeper.theAlgorithm = "MD5";
            keeper.md = MessageDigest.getInstance(keeper.theAlgorithm);
            return keeper;
        }

        public static AccessKeeper create(String theAlgorithm) throws NoSuchAlgorithmException {
            AccessKeeper keeper = new AccessKeeper();
            keeper.theAlgorithm = theAlgorithm;
            keeper.md = MessageDigest.getInstance(keeper.theAlgorithm);
            return keeper;
        }
        
        public static AccessKeeper create(Boolean debugMode) throws NoSuchAlgorithmException {
            AccessKeeper keeper = AccessKeeper.Factory.create();
            keeper.debugMode = true;
            return keeper;
        } 
    }

    protected static String byte2Hex(byte b) {
        String[] hex = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"};
        int i = b;
        if (i < 0) {
            i += 256;
        }
        return hex[i / 16] + hex[i % 16];
    }

    protected String obtainPasswordCutHead(String oriPassword) {
        String strongPassword = null;
        int cutLength = oriPassword.length() / 3;
        int startIndex = 0 + cutLength;
        strongPassword = oriPassword.substring(startIndex, oriPassword.length());
        return strongPassword;
    }

    protected String obtainPasswordCutTail(String oriPassword) {
        String strongPassword = null;
        int cutLength = oriPassword.length() / 3;
        int endIndex = oriPassword.length() - cutLength;
        strongPassword = oriPassword.substring(0, endIndex);
        return strongPassword;
    }

    protected String createPassowrd(Object... inputs) {
        String thePassword = null;
        String str = "";
        for (Object input : inputs) {
            str += input.toString() + middlePk;
        }
        str = prefixPk + str + suffixPk;
        byte[] encodeByte = md.digest(str.getBytes());
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < encodeByte.length; i++) {
            sb.append(byte2Hex(encodeByte[i]));
        }

        thePassword = sb.toString();
        return thePassword;
    }

    
    
    public String createStrongPassword(Object... inputs) {
        return this.createStrongPassword(Method.NoHeadAndNoTail.getCode(), inputs);
    }

    public String createStrongPassword(int way, Object... inputs) {
        String strongPassword = null;
        String oriPassword = createPassowrd(inputs);

        Method designatedMethod = Method.codeOf(way);
        switch (designatedMethod) {
            case NoHead: {
                strongPassword = this.obtainPasswordCutHead(oriPassword);
                break;
            }
            case NoTail: {
                strongPassword = this.obtainPasswordCutTail(oriPassword);
                break;
            }
            case NoHeadAndNoTail: {
                strongPassword = this.obtainPasswordCutTail(this.obtainPasswordCutHead(oriPassword));
                break;
            }
        }
        return strongPassword;
    }
    
    

    public Boolean checkPassword(String password, Object... inputs) {
        int method = Method.NoHeadAndNoTail.getCode();
        return this.checkPassword(password, method, inputs);
    }

    public Boolean checkPassword(String password, int method, Object... inputs) {
        String rightPassword = this.createStrongPassword(method, inputs);
        return password != null && password.equals(rightPassword);

    }

    public Boolean checkPassword(String password, String strMethod, Object... inputs) {
        if (strMethod != null && !"".equals(strMethod)) {
            Integer method = Integer.parseInt(strMethod);
            return this.checkPassword(password, method, inputs);
        } else {
            return false;
        }
    }

}
