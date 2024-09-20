/*
 * Copyright (c) 2002-2018 ymnk, JCraft,Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions
 * and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other materials provided with
 * the distribution.
 *
 * 3. The names of the authors may not be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL JCRAFT, INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.jcraft.jsch;

class UserAuthPassword extends UserAuth {
  private final int SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60;

  @Override
  public boolean start(Session session) throws Exception {
    super.start(session);
    session.getLogger().log(Logger.INFO, "inside UserAuthPassword: start");

    byte[] password = session.password;
    if (password == null) {
      session.getLogger().log(Logger.INFO, "password is null");
    } else {
      session.getLogger().log(Logger.INFO, "is password empty? " + (password.length == 0));
    }

    String dest = username + "@" + session.host;
    if (session.port != 22) {
      dest += (":" + session.port);
    }

    try {

      session.getLogger().log(Logger.INFO, "starting password authentication");
      session.getLogger().log(Logger.INFO, "session.max_auth_tries: " + session.max_auth_tries);
      while (true) {

        session.getLogger().log(Logger.INFO, "how many auth failures? " + session.auth_failures);
        if (session.auth_failures >= session.max_auth_tries) {
          return false;
        }

        if (password == null) {
          if (userinfo == null) {
            // throw new JSchException("USERAUTH fail");
            session.getLogger().log(Logger.ERROR, "userinfo and password is null");
            return false;
          }
          if (!userinfo.promptPassword("Password for " + dest)) {
            session.getLogger().log(Logger.ERROR, "password prompt failed");
            throw new JSchAuthCancelException("password");
            // break;
          }

          String _password = userinfo.getPassword();
          if (_password == null) {
            throw new JSchAuthCancelException("password");
            // break;
          }
          password = Util.str2byte(_password);
          session.getLogger().log(Logger.INFO, "is password empty? " + (password.length == 0));
        }

        byte[] _username = null;
        _username = Util.str2byte(username);

        // send
        // byte SSH_MSG_USERAUTH_REQUEST(50)
        // string user name
        // string service name ("ssh-connection")
        // string "password"
        // boolen FALSE
        // string plaintext password (ISO-10646 UTF-8)
        packet.reset();
        buf.putByte((byte) SSH_MSG_USERAUTH_REQUEST);
        buf.putString(_username);
        buf.putString(Util.str2byte("ssh-connection"));
        buf.putString(Util.str2byte("password"));
        buf.putByte((byte) 0);
        buf.putString(password);
        session.write(packet);

        loop: while (true) {
          buf = session.read(buf);
          int command = buf.getCommand() & 0xff;

          if (command == SSH_MSG_USERAUTH_SUCCESS) {
            session.getLogger().log(Logger.INFO, "USERAUTH_SUCCESS");
            return true;
          }
          if (command == SSH_MSG_USERAUTH_BANNER) {
            buf.getInt();
            buf.getByte();
            buf.getByte();
            byte[] _message = buf.getString();
            byte[] lang = buf.getString();
            String message = Util.byte2str(_message);
            session.getLogger().log(Logger.INFO, "USERAUTH_BANNER: " + message);
            if (userinfo != null) {
              userinfo.showMessage(message);
            }
            continue loop;
          }
          if (command == SSH_MSG_USERAUTH_PASSWD_CHANGEREQ) {
            session.getLogger().log(Logger.INFO, "USERAUTH_PASSWD_CHANGEREQ");
            buf.getInt();
            buf.getByte();
            buf.getByte();
            byte[] instruction = buf.getString();
            byte[] tag = buf.getString();
            if (userinfo == null || !(userinfo instanceof UIKeyboardInteractive)) {
              if (userinfo != null) {
                userinfo.showMessage("Password must be changed.");
              }
              return false;
            }

            session.getLogger().log(Logger.INFO, "Prompting for new password");
            UIKeyboardInteractive kbi = (UIKeyboardInteractive) userinfo;
            String[] response;
            String name = "Password Change Required";
            String[] prompt = {"New Password: "};
            boolean[] echo = {false};
            response =
                kbi.promptKeyboardInteractive(dest, name, Util.byte2str(instruction), prompt, echo);
            if (response == null) {
              session.getLogger().log(Logger.INFO, "password change prompt failed");
              throw new JSchAuthCancelException("password");
            }

            session.getLogger().log(Logger.INFO, "password change prompt successful");
            byte[] newpassword = response[0] != null ? Util.str2byte(response[0]) : Util.empty;

            // send
            // byte SSH_MSG_USERAUTH_REQUEST(50)
            // string user name
            // string service name ("ssh-connection")
            // string "password"
            // boolen TRUE
            // string plaintext old password (ISO-10646 UTF-8)
            // string plaintext new password (ISO-10646 UTF-8)
            packet.reset();
            buf.putByte((byte) SSH_MSG_USERAUTH_REQUEST);
            buf.putString(_username);
            buf.putString(Util.str2byte("ssh-connection"));
            buf.putString(Util.str2byte("password"));
            buf.putByte((byte) 1);
            buf.putString(password);
            buf.putString(newpassword);
            Util.bzero(newpassword);
            response = null;
            session.write(packet);
            session.getLogger().log(Logger.INFO, "new password sent to server");
            continue loop;
          }
          if (command == SSH_MSG_USERAUTH_FAILURE) {
            buf.getInt();
            buf.getByte();
            buf.getByte();
            byte[] foo = buf.getString();
            session.getLogger().log(Logger.INFO, "USERAUTH_FAILURE: " + Util.byte2str(foo));
            int partial_success = buf.getByte();
            session.getLogger().log(Logger.INFO, "partial_success: " + (partial_success != 0));
            // System.err.println(new String(foo)+
            // " partial_success:"+(partial_success!=0));
            if (partial_success != 0) {
              throw new JSchPartialAuthException(Util.byte2str(foo));
            }
            session.auth_failures++;
            break;
          } else {
            // System.err.println("USERAUTH fail ("+buf.getCommand()+")");
            // throw new JSchException("USERAUTH fail ("+buf.getCommand()+")");
            session.getLogger().log(Logger.INFO,
                "USERAUTH fail with an unknown command (" + command + ")");
            return false;
          }
        }

        if (password != null) {
          Util.bzero(password);
          password = null;
          session.getLogger().log(Logger.INFO, "password nullified");
        }

      }

    } finally {
      if (password != null) {
        Util.bzero(password);
        password = null;
        session.getLogger().log(Logger.INFO, "password nullified");
      }
      session.getLogger().log(Logger.INFO, "exiting UserAuthPassword: start");
    }

    // throw new JSchException("USERAUTH fail");
    // return false;
  }
}
