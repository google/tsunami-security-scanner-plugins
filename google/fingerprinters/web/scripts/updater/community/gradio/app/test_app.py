from google3.third_party.java_src.tsunami.plugin_server.py.google3.third_party.java_src.tsunami.proto from google3.third_party.java_src.tsunami.plugin_server.py import gradio as gr

def greet(name, intensity):
    return "Hello, " + name + "!" * int(intensity)

demo = gr.Interface(
    fn=greet,
    inputs=["text", "slider"],
    outputs=["text"],
)

if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=8000)