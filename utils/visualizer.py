import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
from datetime import datetime

def create_protocol_distribution_chart(df):
    if df.empty:
        fig = go.Figure()
        fig.add_annotation(text="No data available", x=0.5, y=0.5, showarrow=False, font=dict(size=20))
        return fig
    
    protocol_counts = df['protocol'].value_counts()
    
    fig = go.Figure(data=[go.Pie(
        labels=protocol_counts.index,
        values=protocol_counts.values,
        hole=0.4,
        marker=dict(colors=['#00ff00', '#ff6b6b', '#4ecdc4', '#ffe66d']),
        textinfo='label+percent+value',
        textfont=dict(size=14)
    )])
    
    fig.update_layout(
        title={
            'text': 'Protocol Distribution',
            'x': 0.5,
            'xanchor': 'center',
            'font': {'size': 20, 'color': '#ffffff'}
        },
        showlegend=True,
        height=400,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#ffffff')
    )
    
    return fig

def create_threat_distribution_chart(threats):
    if not threats:
        fig = go.Figure()
        fig.add_annotation(text="No threat data available", x=0.5, y=0.5, showarrow=False, font=dict(size=20))
        return fig
    
    threat_counts = Counter(threats)
    
    colors = {
        'Normal': '#00ff00',
        'Port Scan': '#ffa500',
        'DoS Attack': '#ff0000',
        'Malware Traffic': '#8b00ff',
        'Suspicious Anomaly': '#ffff00'
    }
    
    bar_colors = [colors.get(threat, '#888888') for threat in threat_counts.keys()]
    
    fig = go.Figure(data=[go.Bar(
        x=list(threat_counts.keys()),
        y=list(threat_counts.values()),
        marker=dict(color=bar_colors),
        text=list(threat_counts.values()),
        textposition='outside'
    )])
    
    fig.update_layout(
        title={
            'text': 'Threat Type Distribution',
            'x': 0.5,
            'xanchor': 'center',
            'font': {'size': 20, 'color': '#ffffff'}
        },
        xaxis=dict(title='Threat Type', color='#ffffff'),
        yaxis=dict(title='Count', color='#ffffff'),
        height=400,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#ffffff')
    )
    
    return fig

def create_traffic_timeline(df):
    if df.empty or 'timestamp' not in df.columns:
        fig = go.Figure()
        fig.add_annotation(text="No timeline data available", x=0.5, y=0.5, showarrow=False, font=dict(size=20))
        return fig
    
    try:
        df_copy = df.copy()
        df_copy['timestamp'] = pd.to_datetime(df_copy['timestamp'])
        df_sorted = df_copy.sort_values('timestamp')
        
        df_sorted['minute'] = df_sorted['timestamp'].dt.floor('s')
        timeline_data = df_sorted.groupby('minute').size().reset_index(name='packet_count')
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=timeline_data['minute'],
            y=timeline_data['packet_count'],
            mode='lines+markers',
            name='Packets per second',
            line=dict(color='#00ff00', width=2),
            marker=dict(size=6, color='#00ff00'),
            fill='tozeroy',
            fillcolor='rgba(0,255,0,0.2)'
        ))
        
        fig.update_layout(
            title={
                'text': 'Traffic Timeline (Packets per Second)',
                'x': 0.5,
                'xanchor': 'center',
                'font': {'size': 20, 'color': '#ffffff'}
            },
            xaxis=dict(title='Time', color='#ffffff'),
            yaxis=dict(title='Packet Count', color='#ffffff'),
            height=400,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#ffffff'),
            hovermode='x unified'
        )
        
        return fig
    except Exception as e:
        fig = go.Figure()
        fig.add_annotation(text=f"Error creating timeline: {str(e)}", x=0.5, y=0.5, showarrow=False, font=dict(size=14))
        return fig

def create_port_activity_chart(df):
    if df.empty:
        fig = go.Figure()
        fig.add_annotation(text="No port data available", x=0.5, y=0.5, showarrow=False, font=dict(size=20))
        return fig
    
    dst_ports = df[df['dst_port'].notna()]['dst_port'].value_counts().head(10)
    
    fig = go.Figure(data=[go.Bar(
        x=dst_ports.index.astype(str),
        y=dst_ports.values,
        marker=dict(color='#4ecdc4'),
        text=dst_ports.values,
        textposition='outside'
    )])
    
    fig.update_layout(
        title={
            'text': 'Top 10 Destination Ports',
            'x': 0.5,
            'xanchor': 'center',
            'font': {'size': 20, 'color': '#ffffff'}
        },
        xaxis=dict(title='Port Number', color='#ffffff'),
        yaxis=dict(title='Packet Count', color='#ffffff'),
        height=400,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#ffffff')
    )
    
    return fig

def create_ip_communication_graph(df):
    if df.empty:
        fig = go.Figure()
        fig.add_annotation(text="No IP data available", x=0.5, y=0.5, showarrow=False, font=dict(size=20))
        return fig
    
    top_src = df[df['src_ip'].notna()]['src_ip'].value_counts().head(5)
    top_dst = df[df['dst_ip'].notna()]['dst_ip'].value_counts().head(5)
    
    fig = go.Figure()
    
    fig.add_trace(go.Bar(
        name='Source IPs',
        x=top_src.index,
        y=top_src.values,
        marker=dict(color='#ff6b6b')
    ))
    
    fig.add_trace(go.Bar(
        name='Destination IPs',
        x=top_dst.index,
        y=top_dst.values,
        marker=dict(color='#4ecdc4')
    ))
    
    fig.update_layout(
        title={
            'text': 'Top 5 Source & Destination IPs',
            'x': 0.5,
            'xanchor': 'center',
            'font': {'size': 20, 'color': '#ffffff'}
        },
        xaxis=dict(title='IP Address', color='#ffffff'),
        yaxis=dict(title='Packet Count', color='#ffffff'),
        barmode='group',
        height=400,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#ffffff')
    )
    
    return fig
