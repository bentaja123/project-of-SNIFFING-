
##----- Importation des Modules -----##
from tkinter import *
from tkinter import messagebox
from tkinter import ttk
from tkinter.messagebox import showinfo
from scapy.all import *
from calendar import *
from uuid import getnode as get_mac
from functools import partial
from threading import *
import tkinter as tk
import socket
import struct
import fcntl
import uuid
import datetime
import sqlite3
from sqlite3 import Error
from time import gmtime, strftime
import time
import csv
import sys
#import mariadb
#----------------------------------function SNIFF----------------------------------#

datetime.datetime.now()

def sniffing():
    sniff(iface='wlo1', prn=ann, stop_filter=stop_sniffing)

def ann(pkt):
        try:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            ########################
            mac_src = pkt.src
            mac_dst = pkt.dst
            ########################

            if pkt.haslayer(ICMP):


                tree.insert(parent='', index=0, iid=len(tree.get_children()), text='',
                            values=(
                                len(tree.get_children()) + 1, strftime("%H,%M:%S", gmtime()), src_ip, dst_ip, "ICMP",len(pkt[ICMP]), mac_src,
                                mac_dst, "", "", pkt[Raw].load), tags=('ICMP',))
                insert(len(tree.get_children()) ,strftime("%H,%M:%S", gmtime()), src_ip, dst_ip, "ICMP", len(pkt[ICMP]), mac_src, mac_dst, "", "", str(pkt[Raw].load))
            else:

                src_port = pkt.sport
                dst_port = pkt.dport

                if pkt.haslayer(TCP):


                    tree.insert(parent='', index=0, iid=len(tree.get_children()), text='',
                                values=(
                                len(tree.get_children()) + 1, strftime("%H,%M:%S", gmtime()), src_ip, dst_ip, "TCP", len(pkt[TCP]), mac_src,
                                mac_dst, src_port, dst_port, pkt[Raw].load), tags=('TCP',))
                    insert(len(tree.get_children()) ,strftime("%H,%M:%S", gmtime()), src_ip, dst_ip, "TCP", len(pkt[TCP]), mac_src,
                           mac_dst, src_port, dst_port,str(pkt[Raw].load))
                elif pkt.haslayer(UDP):


                    tree.insert(parent='', index=0, iid=len(tree.get_children()), text='',
                                values=(
                                len(tree.get_children()) + 1,strftime("%H,%M:%S", gmtime()), src_ip, dst_ip, "UDP", len(pkt[UDP]), mac_src,
                                mac_dst, src_port, dst_port, pkt[Raw].load), tags=('UDP',))
                    insert(len(tree.get_children()) ,strftime("%H,%M:%S", gmtime()), src_ip, dst_ip, "UDP", len(pkt[UDP]), mac_src,
                           mac_dst, src_port, dst_port, str(pkt[Raw].load))

        except:
            pass




def stop_sniffing(packet):
    global should_we_stop
    return should_we_stop


def start_button():
    print('Start button clicked.')
    global should_we_stop
    global thread
    global subdomain
    con = sqlite3.connect('SN.db')
    cursor = con.cursor()
    sql1 = '''create TABLE IF NOT EXISTS views(
                NO int ,
                TIME int,
                IP_SRC int,
                IP_DEST int ,
                PROTOCOL varchar(5),
                LENGTH int,
                MAC_SRC int,
                MAC_DEST int,
                src_PORT int, 
                dst_PORT int,
                INFO text)'''
    cursor.execute(sql1)
    sql = '''delete from views'''
    cursor.execute(sql)
    con.commit()

    if (thread is None) or (not thread.is_alive()):
        should_we_stop = False

        thread = threading.Thread(target=sniffing)

        thread.start()


thread = None
should_we_stop = True
subdomain = ''
src_ip_dict = collections.defaultdict(list)


def stop_button():
    print('Stop button clicked')
    global should_we_stop
    # Set to true so no longer sniffs for packets.
    should_we_stop = True

def delete_command():
    tree.delete(*tree.get_children())
    con = sqlite3.connect('SN.db')
    cursor = con.cursor()
    sql = '''delete from views'''
    cursor.execute(sql)
    con.commit()



s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
a = s.getsockname()[0]
s.close()
def getip():
    messagebox.showinfo("My IP adress is :", str(a))






def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', bytes(ifname, 'utf-8')[:15]))
    return ':'.join('%02x' % b for b in info[18:24])


def getmac():
    messagebox.showinfo("My MAC adress is :",getHwAddr('wlo1'))

def about():
    messagebox.showinfo("ABOUT", "SHARK APP \n Application developed by : \n *Bentaja Othmane  \n *Zraidi Maryem \n *Ait Erraki Youssef ")




#----------------------------------base de donn-----------------------------
def search_protocole_ip_port():
    var= str(query_search.get())
    sqlcode(var)


def sqlcode(var):
    con = sqlite3.connect('SN.db')
    cursor = con.cursor()

    sql1 = '''create TABLE IF NOT EXISTS views(
            NO int ,
            TIME int,
            IP_SRC int,
            IP_DEST int ,
            PROTOCOL varchar(5),
            LENGTH int,
            MAC_SRC int,
            MAC_DEST int,
            src_PORT int, 
            dst_PORT int,
            INFO text)'''
    cursor.execute(sql1)
    con.commit()
    print(var)
    if var=='TCP':
        sql = 'select * from views where PROTOCOL="TCP"'
        cursor.execute(sql)
        rows = cursor.fetchall()

        for i in tree.get_children():
            tree.delete(i)

        for row in rows:
            # print(row)  # it print all records in the database
            tree.insert("", tk.END, values=row, tags=('TCP',))
    elif var=="ICMP":
        sql = 'select * from views where PROTOCOL="ICMP"'
        cursor.execute(sql)
        rows = cursor.fetchall()

        for i in tree.get_children():
            tree.delete(i)

        for row in rows:
            # print(row)  # it print all records in the database
            tree.insert("", tk.END, values=row, tags=('ICMP',))

    elif var== "UDP":
        sql = 'select * from views where PROTOCOL="UDP"'
        cursor.execute(sql)
        rows = cursor.fetchall()

        for i in tree.get_children():
            tree.delete(i)

        for row in rows:
            # print(row)  # it print all records in the database
            tree.insert("", tk.END, values=row, tags=('UDP',))

    else:
        sql = 'select * from views where IP_SRC=? or IP_DEST=? or src_PORT=? or dst_PORT=? '
        my=(var,var,var,var)
        cursor.execute(sql,my)
        rows = cursor.fetchall()

        for i in tree.get_children():
            tree.delete(i)
        for row in rows:
            # print(row)  # it print all records in the database
            tree.insert("", tk.END, values=row)






def insert(NO, TIME, IP_SRC, IP_DEST, PROTOCOL, LENGTH, MAC_SRC, MAC_DEST, src_PORT, dst_PORT, INFO):
    con = sqlite3.connect('SN.db')
    cursor = con.cursor()
    sql1 = '''create TABLE IF NOT EXISTS views(
                NO int ,
                TIME int,
                IP_SRC int,
                IP_DEST int ,
                PROTOCOL varchar(5),
                LENGTH int,
                MAC_SRC int,
                MAC_DEST int,
                src_PORT int, 
                dst_PORT int,
                INFO text)'''
    cursor.execute(sql1)
    sqlite_insert_with_param ="INSERT INTO views (NO, TIME, IP_SRC, IP_DEST, PROTOCOL, LENGTH, MAC_SRC, MAC_DEST, src_PORT, dst_PORT, INFO) VALUES (?, ?, ?,?,?,?,?,?,?,?,?)"
    data_tuple=(NO, TIME, IP_SRC, IP_DEST, PROTOCOL, LENGTH, MAC_SRC, MAC_DEST, src_PORT, dst_PORT, INFO)
    cursor.execute(sqlite_insert_with_param, data_tuple)
    con.commit()

def search_date():
    date1=str(Entdt1.get())
    date2 =str(Entdt2.get())
    print(date1)
    print(date2)
    filtre_date(date1, date2)


def filtre_date(dat1,dat2):
    con = sqlite3.connect('SN.db')
    cursor = con.cursor()
    sql1 = '''create TABLE IF NOT EXISTS views(
                    NO int ,
                    TIME int,
                    IP_SRC int,
                    IP_DEST int ,
                    PROTOCOL varchar(5),
                    LENGTH int,
                    MAC_SRC int,
                    MAC_DEST int,
                    src_PORT int, 
                    dst_PORT int,
                    INFO text)'''
    cursor.execute(sql1)
    con.commit()
    sql='''select * from views where TIME between ? and  ? '''
    my=(dat1,dat2)
    cursor.execute(sql,my)
    rows = cursor.fetchall()
    for i in tree.get_children():
        tree.delete(i)
    for row in rows:
        # print(row)  # it print all records in the database
        tree.insert("", tk.END, values=row)




#-----------------------------------------------------------------------------------------------
#----------------------------------------save clean_file open file------------------------------------

def save_csv():
    with open("new.csv", "w", newline='') as myfile:
        csvwriter = csv.writer(myfile, delimiter=',')

        for row_id in tree.get_children():
            row = tree.item(row_id)['values']
            print('save row:', row)
            csvwriter.writerow(row)


def load_csv():
    with open("new.csv") as myfile:
        csvread = csv.reader(myfile, delimiter=',')

        for row in csvread:
            print('load row:', row)
            tree.insert("", 'end', values=row)


def clean_file():
    f = open('new.csv', 'r+')
    f.truncate(0)
    for i in tree.get_children():
        tree.delete(i)









#--------------fenetre---------------#

root = Tk()
root.geometry('1400x630')
root.title("SHARK APP")
style=ttk.Style()
style.theme_use("clam")
style.configure('Treeview',rowheight=20,fieldbackground="gray54")
style.configure('W.TButton', foreground = 'red')
style.configure('cap.TButton', foreground = 'green')
style.configure('f.TButton', foreground = 'gold4')
style.configure('g.TButton', foreground = 'blue')

#--------------menu bar---------------#

menubar = Menu(root,borderwidth=0, bg="oldlace")
filemenu = Menu(menubar, tearoff=1, foreground='black')
filemenu.add_command(label="clean file", command=clean_file)
filemenu.add_command(label="Open", command=load_csv)
filemenu.add_command(label="Save", command=save_csv)
filemenu.add_separator()
filemenu.add_command(label="Exit", command=root.quit)
menubar.add_cascade(label="File", menu=filemenu)



view = Menu(menubar, tearoff=0)
ratio = Menu(menubar, tearoff=0)
for aspected_ratio in ('4:3', '16:9'):
    ratio.add_command(label=aspected_ratio)
view.add_cascade(label='Ratio', menu=ratio)
menubar.add_cascade(label='View', menu=view)


helpmenu = Menu(menubar, tearoff=0)
helpmenu.add_command(label="Help Index")
helpmenu.add_command(label="About...", command=about)

menubar.add_cascade(label="Help", menu=helpmenu)

root.config(menu=menubar)

#--------------  LabelFrame  ---------------#

lf = ttk.LabelFrame( root,width=1400, height=100)
lf.place(x=0,y=0)

l_dt1=Label(root,text='DATE 1 :').place(x=710,y=23)
l_dt2=Label(root,text='DATE 2 :').place(x=710,y=43)

Entdt1=StringVar()
Entdt1.set("--,--:--")
Entdt1_search=ttk.Entry(root,width=22, textvariable=Entdt1).place(x=770,y=23)

Entdt2=StringVar()
Entdt2.set("--,--:--")
Entdt2_search=ttk.Entry(root,width=22, textvariable=Entdt2).place(x=770,y=43)

query_search = StringVar()
query_search.set("protocole_ip_port")
query_search_entry = Entry(root, textvariable=query_search, width=40).place(x=340,y=35)


#--------------  bouton  ---------------#

ttk.Button(root,text='CAPTURE',width=10,command=start_button,style='cap.TButton').place(x=1,y=23)

Bouton_filtr=ttk.Button(root,text="FILTER ",width=10,style='f.TButton',command=search_protocole_ip_port).place(x=610,y=30)
quitter=ttk.Button(root,text='EXIT',width=15,command=quit,style='W.TButton').place(x=1240,y=23)
ip_b=ttk.Button(root,text='GET_IP',width=10,command=getip,style='g.TButton').place(x=100,y=23)
mac_b=ttk.Button(root,text='GET_MAC',width=10,command=getmac,style='g.TButton').place(x=200,y=23)
buton_STOPSNIF=ttk.Button(root,text="STOP SNIFFING", command=stop_button, width=15).place(x=1110,y=23)
b2 = ttk.Button(root, text="DELETE ALL", width=15, command=delete_command).place(x=1110, y=58)
b3=ttk.Button(root,text='FILTER BY DATE',command=search_date,width=15).place(x=960,y=30)


tree=ttk.Treeview(root,show="headings",height=24,style="Treeview")

vsb = ttk.Scrollbar(orient="vertical", command=tree.yview)
vsb.place(x=1385, y=100, height=500)
tree.configure(yscroll=vsb.set)

vsbx = ttk.Scrollbar(root, orient="horizontal", command=tree.xview)
vsbx.place(x=1, y=600, width=1395)
tree.configure(xscrollcommand=vsbx.set)


tree["columns"]=("zero","one","two","three","four","five","six","seven","eight","nine","ten")
tree.column("zero", width=40, minwidth=30, stretch=tk.NO)
tree.column("one", width=120, minwidth=200, stretch=tk.NO)
tree.column("two", width=130, minwidth=190,stretch=tk.NO)
tree.column("three", width=130, minwidth=190, stretch=tk.NO)
tree.column("four", width=90, minwidth=50, stretch=tk.NO)
tree.column("five", width=70, minwidth=80, stretch=tk.NO)
tree.column("six", width=150, minwidth=190, stretch=tk.NO)
tree.column("seven", width=150, minwidth=190, stretch=tk.NO)
tree.column("eight", width=90, minwidth=190, stretch=tk.NO)
tree.column("nine", width=90, minwidth=190, stretch=tk.NO)
tree.column("ten", width=900, minwidth=80, stretch=tk.NO)

tree.heading("zero",text="NO",anchor=tk.W)
tree.heading("one", text="TIME",anchor=tk.W)
tree.heading("two", text="IP_SRC",anchor=tk.W)
tree.heading("three", text="IP_DEST",anchor=tk.W)
tree.heading("four", text="PROTOCOL",anchor=tk.W)
tree.heading("five", text="LENGTH",anchor=tk.W)
tree.heading("six", text="MAC_SRC",anchor=tk.W)
tree.heading("seven", text="MAC_DEST",anchor=tk.W)
tree.heading("eight", text="src_PORT",anchor=tk.W)
tree.heading("nine", text="dst_PORT",anchor=tk.W)
tree.heading("ten", text="INFO",anchor=tk.W)

tree.tag_configure('TCP', background='turquoise')
tree.tag_configure('UDP', background='light salmon')
tree.tag_configure('ICMP', background='lemon chiffon')

tree.place(x=0, y=90)




#--------------fin---------------#


root.mainloop()






































