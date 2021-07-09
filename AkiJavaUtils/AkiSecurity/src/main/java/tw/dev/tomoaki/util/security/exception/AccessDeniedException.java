/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package tw.dev.tomoaki.util.security.exception;

/**
 *
 * @author Tomoaki Chen
 */
public class AccessDeniedException extends RuntimeException {

    public AccessDeniedException() {
        super();
    }

    public AccessDeniedException(String msg) {
        super(msg);
    }

    public AccessDeniedException(Exception ex) {
        super(ex);
    }
}
