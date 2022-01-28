import idaapi
import ida_kernwin

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import *

from ekko.ui.utils import *
from ekko.store.profile import *
from ekko.store.snapshot import SnapshotStore
from ekko.qemu.qemu import QEMU

class VMSnapshotWidget(QWidget):
    DEFAULT_LABEL_WIDTH = 80
    SMALL_BUTTON_WIDTH = 50
    LARGE_BUTTON_WIDTH = 100
    DEFAULT_LINE_EDIT_WIDTH = 300

    def __init__(self, parent, vm_name):
        super().__init__(parent)
        self.parent = parent
        self.vm_name = vm_name
        self.qemu = QEMU.create_instance(vm_name)

        self._create_widget()
        self._setup_layout()
        self._load_snapshots()

    def _create_widget(self):
        # Groups
        self.group_snapshots = QGroupBox("Snapshots")
        self.group_snapshot_config = QGroupBox("Snapshot configuration")

        # Group splitter
        self.splitter_group = QSplitter(Qt.Horizontal)
        self.splitter_group.addWidget(self.group_snapshots)
        self.splitter_group.addWidget(self.group_snapshot_config)
        self.splitter_group.setStretchFactor(0, 1)

        # Table
        self.tbl_snapshots = TTable(['Tag', 'Name', 'Description', 'On debugging', 'Address', ''])
        self.tbl_snapshots.setRowCount(0)
        self.tbl_snapshots.resize_columns([100, 160, 160, 100, 70, 1])
        self.tbl_snapshots.itemSelectionChanged.connect(self.tbl_snapshots_row_selected)

        # Text box
        self.box_tag = QLineEdit('')
        self.box_tag.setReadOnly(True)
        self.box_tag.setFixedWidth(self.DEFAULT_LINE_EDIT_WIDTH)

        self.box_name = QLineEdit('')
        self.box_name.setFixedWidth(self.DEFAULT_LINE_EDIT_WIDTH)

        self.box_description = QLineEdit('')
        self.box_description.setFixedWidth(self.DEFAULT_LINE_EDIT_WIDTH)

        self.box_on_debugging = QLineEdit('')
        self.box_on_debugging.setReadOnly(True)
        self.box_on_debugging.setFixedWidth(self.DEFAULT_LINE_EDIT_WIDTH)

        self.box_address = QLineEdit('')
        self.box_address.setReadOnly(True)
        self.box_address.setFixedWidth(self.DEFAULT_LINE_EDIT_WIDTH)

        # Buttons
        self.btn_take_snapshot = QPushButton("Take snapshot")
        self.btn_take_snapshot.clicked.connect(self.btn_take_snapshot_clicked)
        self.btn_take_snapshot.setFixedWidth(self.LARGE_BUTTON_WIDTH)

        self.btn_load_snapshot = QPushButton("Load snapshot")
        self.btn_load_snapshot.clicked.connect(self.btn_load_snapshot_clicked)
        self.btn_load_snapshot.setFixedWidth(self.LARGE_BUTTON_WIDTH)

        self.btn_save = QPushButton("Save")
        self.btn_save.clicked.connect(self.btn_save_clicked)
        self.btn_save.setFixedWidth(self.SMALL_BUTTON_WIDTH)

        self.btn_delete = QPushButton("Delete")
        self.btn_delete.clicked.connect(self.btn_delete_clicked)
        self.btn_delete.setFixedWidth(self.SMALL_BUTTON_WIDTH)

    def _setup_layout(self):
        # snapshots group
        vbox = make_vbox(
            self.tbl_snapshots,
            make_hbox(self.btn_take_snapshot, align_left=True)
        )
        self.group_snapshots.setLayout(vbox)

        # snapshot datail group
        vbox = make_vbox(
            make_hbox(
                ("Tag", self.DEFAULT_LABEL_WIDTH), ": ",
                self.box_tag,
                align_left=True,
            ),
            make_hbox(
                ("Name", self.DEFAULT_LABEL_WIDTH), ": ",
                self.box_name,
                align_left=True,
            ),
            make_hbox(
                ("Description", self.DEFAULT_LABEL_WIDTH), ": ",
                self.box_description,
                align_left=True,
            ),
            make_hbox(
                ("On debugging", self.DEFAULT_LABEL_WIDTH), ": ",
                self.box_on_debugging,
                align_left=True,
            ),
            make_hbox(
                ("Address", self.DEFAULT_LABEL_WIDTH), ": ",
                self.box_address,
                align_left=True,
            ),
            make_hbox(
                self.btn_load_snapshot, self.btn_save, self.btn_delete,
                align_left=True
            ),
        )
        self.group_snapshot_config.setLayout(vbox)

        # main layout
        main_layout = make_hbox(
            self.splitter_group
        )
        self.setLayout(main_layout)

    def _load_snapshots(self):
        self.tbl_snapshots.setRowCount(0)

        snapshots_info = SnapshotStore.get_snapshots_info(self.vm_name)
        for idx, (_, info) in enumerate(snapshots_info.items()):
            self.tbl_snapshots.insertRow(idx)

            it_tag = QTableWidgetItem(info['tag'])
            it_tag.setTextAlignment(Qt.AlignCenter)

            it_name = QTableWidgetItem(info['name'])
            it_name.setTextAlignment(Qt.AlignCenter)

            it_description = QTableWidgetItem(info['description'])
            it_description.setTextAlignment(Qt.AlignCenter)

            it_on_debugging = QTableWidgetItem(info['on_debugging'])
            it_on_debugging.setTextAlignment(Qt.AlignCenter)

            it_address = QTableWidgetItem(info['address'])
            it_address.setTextAlignment(Qt.AlignCenter)

            self.tbl_snapshots.setItem(idx, 0, it_tag)
            self.tbl_snapshots.setItem(idx, 1, it_name)
            self.tbl_snapshots.setItem(idx, 2, it_description)
            self.tbl_snapshots.setItem(idx, 3, it_on_debugging)
            self.tbl_snapshots.setItem(idx, 4, it_address)

    def _clean_snapshot_input(self):
        self.box_tag.setText("")
        self.box_name.setText("")
        self.box_description.setText("")
        self.box_on_debugging.setText("")
        self.box_address.setText("")

    def tbl_snapshots_row_selected(self):
        items = self.tbl_snapshots.selectedItems()
        if len(items) > 0:
            self.box_tag.setText(items[0].text())
            self.box_name.setText(items[1].text())
            self.box_description.setText(items[2].text())
            self.box_on_debugging.setText(items[3].text())
            self.box_address.setText(items[4].text())

    def btn_save_clicked(self):
        SnapshotStore.update_snapshot_info(
            self.vm_name,
            self.box_tag.text(),
            name = self.box_name.text(),
            description = self.box_description.text(),
        )

        self._load_snapshots()
    
    def btn_delete_clicked(self):
        if self.box_tag.text() != "":
            res, err = self.qemu.delete_snapshot(self.box_tag.text())
            if err:
                ida_kernwin.warning(err)
                return
                
            SnapshotStore.delete_snapshot_info(self.vm_name, self.box_tag.text())

            self._clean_snapshot_input()
            self._load_snapshots()

    def btn_take_snapshot_clicked(self):
        from ekko.ui.dialog.create_snapshot import CreateSnapshotDialog
        dialog = CreateSnapshotDialog(self.parent, self.vm_name)
        dialog.exec_()

        if dialog.snapshot_created:
            snapshots_info = SnapshotStore.get_snapshots_info(self.vm_name)
            tag = list(snapshots_info)[-1]

            _, err = self.qemu.take_snapshot(tag)
            if err:
                ida_kernwin.warning(err)
                SnapshotStore.delete_snapshot_info(self.vm_name, tag)

            self._load_snapshots()

    def btn_load_snapshot_clicked(self):
        if self.box_tag.text() != "":
            res, err = self.qemu.load_snapshot(
                self.box_tag.text(),
                self.box_on_debugging.text() == "True"
            )
            if err:
                ida_kernwin.warning(err)

# -----------------------------------------------------------------------
# HeapViewer - by @danigargu
class TTable(QTableWidget):
    def __init__(self, labels, parent=None):
        super(TTable, self).__init__(parent)
        self.labels = labels
        self.setColumnCount(len(labels))
        self.setHorizontalHeaderLabels(labels)
        self.verticalHeader().hide()
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        #self.horizontalHeader().model().setHeaderData(0, Qt.Horizontal, 
        #    Qt.AlignJustify, Qt.TextAlignmentRole)    
        self.horizontalHeader().setStretchLastSection(1)
        self.setSelectionMode(QTableView.SingleSelection)
        self.setSelectionBehavior(QTableView.SelectRows)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)

    def copy_selected_value(self):
        item = self.currentItem()
        if item is not None:
            QApplication.clipboard().setText(item.text())

    def copy_selected_row(self):
        selection = self.selectionModel()
        indexes = selection.selectedRows()
        if len(indexes) < 1:
            return
        text = ''
        for idx in indexes:
            row = idx.row()
            for col in range(0, self.columnCount()):
                item = self.item(row, col)
                if item:
                    text += item.text()
                text += '\t'
            text += '\n'
        QApplication.clipboard().setText(text)

    def dump_table_as_csv(self):
        result = ''
        result += ';'.join(self.labels) + "\n"
        for i in range(0, self.rowCount()):
            columns = []
            for j in range(0, self.columnCount()):
                item = self.item(i, j).text()
                columns.append(item)
            result += ';'.join(columns) + "\n"
        return result

    def resize_columns(self, widths):
        for i, val in enumerate(widths):
            self.setColumnWidth(i, val)

    def resize_to_contents(self):
        self.resizeRowsToContents()
        self.resizeColumnsToContents()

    def set_row_color(self, num_row, color):
        for i in range(self.columnCount()):
            self.item(num_row, i).setBackground(color)

    def clear_table(self):
        self.setRowCount(0)