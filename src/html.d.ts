/** assets/pages/*.html 以文本形式内嵌（esbuild --loader:.html=text），仅供单文件打包入口使用 */
declare module '*.html' {
  const content: string;
  export default content;
}
