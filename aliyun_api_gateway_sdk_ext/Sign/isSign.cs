using aliyun_api_gateway_sdk.Util;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.Configuration;
namespace aliyun_api_gateway_sdk_ext.Sign
{
    public class isSign
    {
        private static String appKey = WebConfigurationManager.AppSettings["appKey"];
        private static String appSecret = WebConfigurationManager.AppSettings["appSecret"];

        public static bool Sign(System.Web.HttpContext context)
        {

            Dictionary<String, String> headers = new Dictionary<string, string>();
            Dictionary<String, String> querys = new Dictionary<string, string>();
            Dictionary<String, String> bodys = new Dictionary<string, string>();
            List<String> signHeader = new List<String>();
            string returnstr = "false";
            string signH = context.Request.Headers["X-Ca-Signature-Headers"];
            string path = context.Request.Path;
            string method = context.Request.HttpMethod;
            string host = context.Request.Headers["Host"];
            string Signature = context.Request.Headers["X-Ca-Signature"];
            HttpRequest request = context.Request;
            Stream stream = request.InputStream;
            string json = string.Empty;
            string responseJson = string.Empty;
            if (stream.Length != 0)
            {
                StreamReader streamReader = new StreamReader(stream);
                json = streamReader.ReadToEnd();
            }
            //bodys.Add("", HttpUtility.UrlDecode(json));
            foreach (string key in request.Form)
            {
                bodys.Add(key, request.Form[key]);
            }
            
            foreach (String key in context.Request.Headers)
            {
                if (key != "X-Ca-Signature-Headers" && key != "X-Natapp-Ip" && key != "X-Real-Ip" && key != "Host" && key != "Connection" && key != "Content-Length" && key != "X-Ca-Signature")
                {
                    headers.Add(key, context.Request.Headers[key]);
                }
                //signHeader.Add(key);
            }
            if (signH != null)
            {
                foreach (String key in signH.Split(','))
                {

                    //headers.Add(key,context.Request.Headers[key]);
                    signHeader.Add(key);

                }
            }
            foreach (String key in context.Request.QueryString)
            {

                querys.Add(key, context.Request.QueryString[key]);

            }


            string Signature_now = SignUtil.Sign(path, method, appSecret, headers, querys, bodys, signHeader);
            if (Signature_now == Signature)
            {
                return true;
            }
            return false;
        }
    }
}