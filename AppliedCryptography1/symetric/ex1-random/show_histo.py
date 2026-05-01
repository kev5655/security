try:
    import pandas as pd
    import plotly.express as px
except ModuleNotFoundError as exc:
    raise SystemExit(
        "Missing dependency. Install with: pip install pandas plotly"
    ) from exc

# 1. Load the CSV file
df = pd.read_csv("latency_data.csv")

# 2. Normalize and validate numeric columns
df["Latency_ns"] = pd.to_numeric(df["Latency_ns"], errors="coerce")
df["Count"] = pd.to_numeric(df["Count"], errors="coerce")
df = df.dropna(subset=["Latency_ns", "Count"])
df = df[df["Count"] > 0]

if df.empty:
    raise ValueError("No valid data found in latency_data.csv")

# 3. Build a weighted histogram instead of one bar per raw x value.
# This avoids ultra-thin bars that can look like a blank chart.
fig = px.histogram(
    df,
    x="Latency_ns",
    y="Count",
    histfunc="sum",
    nbins=120,
    title="Go Scheduler Latency Distribution (Nanoseconds)",
    labels={"Latency_ns": "Latency (ns)", "Count": "Frequency"},
)

fig.update_layout(template="plotly_white", bargap=0.03)
fig.update_xaxes(type="log")

# 4. Save result to HTML
fig.write_html("my_graph.html")

print("Success! Open my_graph.html in your browser.")