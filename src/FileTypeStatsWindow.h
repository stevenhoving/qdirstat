/*
 *   File name: FileTypeStatsWindow.h
 *   Summary:    QDirStat file type statistics window
 *   License:    GPL V2 - See file LICENSE for details.
 *
 *   Author:    Stefan Hundhammer <Stefan.Hundhammer@gmx.de>
 */


#ifndef FileTypeStatsWindow_h
#define FileTypeStatsWindow_h

#include <QDialog>
#include <QMap>
#include <QTreeWidgetItem>
#include <QPointer>

#include "ui_file-type-stats-window.h"
#include "Subtree.h"


namespace QDirStat
{
    class DirTree;
    class FileInfo;
    class FileTypeStats;
    class MimeCategory;
    class SelectionModel;
    class LocateFilesWindow;


    /**
     * Modeless dialog to display file type statistics, such as how much disk
     * space is used for each kind of filename extension (*.jpg, *.mp4 etc.).
     **/
    class FileTypeStatsWindow: public QDialog
    {
    Q_OBJECT

    public:

    /**
     * Constructor.
         *
         * This creates a file type statistics window, but it does not populate
         * it with content yet.
     *
     * Notice that this widget will destroy itself upon window close.
     *
     * It is advised to use a QPointer for storing a pointer to an instance
     * of this class. The QPointer will keep track of this window
     * auto-deleting itself when closed.
     **/
    FileTypeStatsWindow( SelectionModel * selectionModel,
                 QWidget *          parent );

    /**
     * Destructor.
     **/
    virtual ~FileTypeStatsWindow();

    public:

        /**
         * Obtain the subtree from the last used URL.
         **/
        const Subtree & subtree() const { return _subtree; }

    /**
     * Populate the widgets for a subtree.
     **/
    void populate( FileInfo * subtree );


    public slots:

    /**
     * Refresh (reload) all data.
     **/
    void refresh();

    /**
     * Open a "Locate File Type" window for the currently selected file
     * type or re-populate it if it is still open.
     **/
    void locateCurrentFileType();

        /**
         * Open a "File Size Statistics" window for the currently selected file
         * type or re-popuolate it if it is still open.
         **/
    void sizeStatsForCurrentFileType();

    /**
     * Reject the dialog contents, i.e. the user clicked the "Cancel"
     * or WM_CLOSE button.
     *
     * Reimplemented from QDialog.
     **/
    virtual void reject() Q_DECL_OVERRIDE;

    protected slots:

    /**
     * Enable or disable the actions depending on the current item.
     **/
    void enableActions( QTreeWidgetItem * currentItem );

    protected:

    /**
     * Clear all data and widget contents.
     **/
    void clear();

    /**
     * One-time initialization of the widgets in this window.
     **/
    void initWidgets();

        /**
         * Return the suffix of the currently selected file type or an empty
         * string if no suffix is selected.
         **/
        QString currentSuffix() const;


    //
    // Data members
    //

    Ui::FileTypeStatsWindow *   _ui;
        Subtree                     _subtree;
    SelectionModel *        _selectionModel;
    FileTypeStats *            _stats;
    static QPointer<LocateFilesWindow> _locateFilesWindow;
    };


    /**
     * Column numbers for the file type tree widget
     **/
    enum FileTypeColumns
    {
    FT_NameCol = 0,
    FT_CountCol,
    FT_TotalSizeCol,
    FT_PercentageCol,
    FT_ColumnCount
    };


    /**
     * Item class for the file type tree widget, representing either a MIME
     * category or a suffix.
     **/
    class FileTypeItem: public QTreeWidgetItem
    {
    public:

    /**
     * Constructor. After creating, this item has to be inserted into the
     * tree at the appropriate place: Toplevel for categories, below a
     * category for suffixes.
     **/
    FileTypeItem( const QString & name,
              int          count,
              FileSize          totalSize,
              float          percentage );
    //
    // Getters
    //

    QString     name()          const { return _name; }
    int     count()      const { return _count; }
    FileSize totalSize()  const { return _totalSize; }
    float     percentage() const { return _percentage; }

    /**
     * Set the font to bold face for all columns.
     **/
    void setBold();

    /**
     * Less-than operator for sorting.
     **/
    virtual bool operator<(const QTreeWidgetItem & other) const Q_DECL_OVERRIDE;

    protected:

    QString        _name;
    int        _count;
    FileSize    _totalSize;
    float        _percentage;
    };


    /**
     * Specialized item class for MIME categories.
     **/
    class CategoryFileTypeItem: public FileTypeItem
    {
    public:

    /**
     * Constructor.
     **/
    CategoryFileTypeItem( MimeCategory * category,
                  int         count,
                  FileSize         totalSize,
                  float         percentage );

    /**
     * Return the MIME category of this item.
     **/
    MimeCategory * category() const { return _category; }

    protected:

    MimeCategory * _category;
    };


    /**
     * Specialized item class for suffix file types.
     **/
    class SuffixFileTypeItem: public FileTypeItem
    {
    public:

    /**
     * Constructor.
     **/
    SuffixFileTypeItem( const QString & suffix,
                int            count,
                FileSize        totalSize,
                float        percentage );

    /**
     * Return this file type's suffix.
     **/
    QString suffix() const { return _suffix; }

    protected:

    QString _suffix;
    };


    /**
     * Functor for std::sort to compare FileTypeItems by size descending.
     **/
    struct FileTypeItemCompare
    {
    bool operator() ( FileTypeItem * a, FileTypeItem * b )
        { return a->totalSize() > b->totalSize(); }
    };

} // namespace QDirStat


#endif // FileTypeStatsWindow_h
