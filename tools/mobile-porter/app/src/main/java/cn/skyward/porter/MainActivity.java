package cn.skyward.porter;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.graphics.drawable.StateListDrawable;
import android.widget.ImageView;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;

/** Offline UI. Only the explicit destructive dialog can call Porter.flash. */
public final class MainActivity extends Activity {
    private static final int SAVE_BACKUP = 11;
    private static final int TEXT = 0xFF211934;
    private static final int MUTED = 0xFF6B617B;
    private static final int ACCENT = 0xFF6146C5;
    private static final int WARN = 0xFFA12D43;
    private static final int CARD = Color.WHITE;
    private static final int LINE = 0xFFE6E0EF;
    private static final int TINT = 0xFFF1EBFF;
    private static final String PGZ110 = "PGZ110";
    private static final String PGJM10 = "PGJM10";
    private Session session;
    private RadioButton acerace;
    private RadioButton k10;
    private Button prepare;
    private Button flash;
    private Button exportVendor;
    private Button exportVbmeta;
    private TextView status;
    private TextView files;
    private TextView log;
    private View logCard;
    private View resultCard;
    private ProgressBar progress;
    private AlertDialog confirmation;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        Object retained = getLastNonConfigurationInstance();
        session = retained instanceof Session ? (Session) retained : new Session(getApplicationContext());
        buildScreen();
        session.attach(this);
    }

    @Override public Object onRetainNonConfigurationInstance() {
        return session;
    }

    @Override protected void onDestroy() {
        if (confirmation != null) confirmation.dismiss();
        if (session != null) session.detach(this);
        super.onDestroy();
    }

    @SuppressWarnings("deprecation")
    @Override public void onBackPressed() {
        if (session.blocked()) {
            Toast.makeText(this, R.string.busy, Toast.LENGTH_SHORT).show();
        } else {
            super.onBackPressed();
        }
    }

    private void buildScreen() {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setFitsSystemWindows(true);
        LinearLayout content = vertical();
        content.setPadding(dp(20), dp(18), dp(20), dp(28));
        scroll.addView(content);
        setContentView(scroll);

        LinearLayout hero = vertical();
        GradientDrawable gradient = new GradientDrawable(GradientDrawable.Orientation.TL_BR,
                new int[]{0xFF211749, 0xFF49338C});
        gradient.setCornerRadius(dp(26));
        hero.setBackground(gradient);
        hero.setPadding(dp(22), dp(20), dp(22), dp(22));
        add(content, hero, 0);
        LinearLayout brand = new LinearLayout(this);
        brand.setGravity(Gravity.CENTER_VERTICAL);
        ImageView icon = new ImageView(this);
        icon.setImageResource(R.drawable.porter_icon);
        icon.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        brand.addView(icon, new LinearLayout.LayoutParams(dp(44), dp(44)));
        TextView eyebrow = text("SKYWARD  /  PORTER", 12, 0xFFE4D9FF);
        eyebrow.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        eyebrow.setLetterSpacing(.10f);
        LinearLayout.LayoutParams brandText = new LinearLayout.LayoutParams(0, -2, 1);
        brandText.leftMargin = dp(12);
        brand.addView(eyebrow, brandText);
        add(hero, brand, 0);
        TextView heading = text(getString(R.string.heading), 28, Color.WHITE);
        heading.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        add(hero, heading, 12);
        add(hero, text(getString(R.string.introduction), 14, 0xFFEDE7FF), 8);

        LinearLayout options = card();
        add(content, options, 16);
        add(options, step("01", R.string.choose_model), 0);
        RadioGroup modelGroup = new RadioGroup(this);
        modelGroup.setOrientation(RadioGroup.VERTICAL);
        acerace = choice(R.string.pgz110);
        k10 = choice(R.string.pgjm10);
        modelGroup.addView(acerace);
        modelGroup.addView(k10);
        if (session.model != null) modelGroup.check(PGJM10.equals(session.model) ? k10.getId() : acerace.getId());
        modelGroup.setOnCheckedChangeListener((group, id) -> {
            String value = id == k10.getId() ? PGJM10 : PGZ110;
            if (!session.blocked() && !value.equals(session.model)) {
                session.model = value;
                session.flashAllowed = false;
                if (session.statusId != R.string.flash_failed) session.setStatus(R.string.idle, null);
                else session.changed();
            }
        });
        add(options, modelGroup, 10);
        LinearLayout preparation = card();
        add(content, preparation, 12);
        add(preparation, step("02", R.string.prepare_title), 0);
        prepare = button(R.string.prepare, ACCENT, Color.WHITE, ACCENT);
        prepare.setOnClickListener(v -> session.prepare());
        add(preparation, prepare, 12);

        status = text("", 14, TEXT);
        status.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        add(preparation, status, 10);
        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progress.setIndeterminate(true);
        add(preparation, progress, 6);

        LinearLayout output = card();
        resultCard = output;
        add(content, output, 14);
        add(output, step("03", R.string.details), 0);
        files = text("", 14, MUTED);
        files.setTextIsSelectable(true);
        add(output, files, 8);
        exportVendor = button(R.string.export_vendor);
        exportVendor.setOnClickListener(v -> chooseExport(false));
        add(output, exportVendor, 12);
        exportVbmeta = button(R.string.export_vbmeta);
        exportVbmeta.setOnClickListener(v -> chooseExport(true));
        add(output, exportVbmeta, 4);
        flash = button(R.string.flash, 0xFFFDECF0, WARN, 0xFFF7CDD7);
        flash.setOnClickListener(v -> confirmFlash());
        add(output, flash, 14);

        LinearLayout logs = card();
        logCard = logs;
        add(content, logs, 12);
        add(logs, label(R.string.logs), 0);
        log = text("", 13, MUTED);
        log.setTypeface(Typeface.MONOSPACE);
        log.setTextIsSelectable(true);
        add(logs, log, 6);
        TextView author = text(getString(R.string.author), 14, MUTED);
        author.setGravity(Gravity.CENTER);
        add(content, author, 20);
    }

    private void render() {
        boolean blocked = session.blocked();
        boolean writing = session.statusId == R.string.flashing || session.statusId == R.string.flash_failed;
        status.setTextColor(writing ? WARN : TEXT);
        status.setText(session.statusArg == null ? getString(session.statusId)
                : getString(session.statusId, session.statusArg));
        progress.setVisibility(session.busy ? View.VISIBLE : View.GONE);
        acerace.setEnabled(!blocked);
        k10.setEnabled(!blocked);
        prepare.setEnabled(!blocked && session.model != null);
        Porter.Prepared p = session.prepared;
        resultCard.setVisibility(p == null ? View.GONE : View.VISIBLE);
        if (p != null) {
            files.setText(getString(R.string.prepared_files, p.slot, p.image.getPath(), p.vbmetaImage.getPath(),
                    p.backup.getPath(), p.vbmetaBackup.getPath()));
            flash.setEnabled(session.canFlash(p));
            exportVendor.setEnabled(!blocked && p.backup.isFile());
            exportVbmeta.setEnabled(!blocked && p.vbmetaBackup.isFile());
            exportVendor.setText(session.vendorDocument == null ? R.string.export_vendor : R.string.export_vendor_done);
            exportVbmeta.setText(session.vbmetaDocument == null ? R.string.export_vbmeta : R.string.export_vbmeta_done);
        }
        String messages = session.messages.toString();
        logCard.setVisibility(messages.isEmpty() ? View.GONE : View.VISIBLE);
        log.setText(messages);
    }

    private void confirmFlash() {
        Porter.Prepared p = session.prepared;
        if (!session.canFlash(p) || confirmation != null) return;
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(R.string.confirm_title)
                .setMessage(getString(R.string.confirm_message, p.slot))
                .setNegativeButton(R.string.cancel, null)
                .setPositiveButton(R.string.confirm_flash, (ignored, which) -> session.flash(p))
                .create();
        confirmation = dialog;
        dialog.setOnDismissListener(ignored -> { if (confirmation == dialog) confirmation = null; });
        dialog.show();
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(WARN);
    }

    private void chooseExport(boolean vbmeta) {
        Porter.Prepared p = session.prepared;
        if (session.blocked() || p == null) return;
        File backup = vbmeta ? p.vbmetaBackup : p.backup;
        if (!backup.isFile()) return;
        Intent save = new Intent(Intent.ACTION_CREATE_DOCUMENT)
                .addCategory(Intent.CATEGORY_OPENABLE).setType("application/octet-stream")
                .putExtra(Intent.EXTRA_TITLE, getString(vbmeta ? R.string.backup_vbmeta_name : R.string.backup_vendor_name));
        session.pendingExport = backup;
        session.changed();
        try {
            startActivityForResult(save, SAVE_BACKUP);
        } catch (RuntimeException failure) {
            session.pendingExport = null;
            session.setStatus(R.string.export_picker_failed, describe(failure));
        }
    }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request != SAVE_BACKUP) return;
        File source = session.pendingExport;
        session.pendingExport = null;
        Uri destination = data == null ? null : data.getData();
        if (result == RESULT_OK && source != null && destination != null) {
            session.exportBackup(source, destination);
        } else {
            session.changed();
        }
    }

    private LinearLayout vertical() {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        return layout;
    }

    private LinearLayout card() {
        LinearLayout layout = vertical();
        layout.setBackground(shape(CARD, LINE, 22));
        layout.setPadding(dp(16), dp(16), dp(16), dp(16));
        return layout;
    }

    private void add(LinearLayout parent, View child, int top) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2);
        params.topMargin = dp(top);
        parent.addView(child, params);
    }

    private TextView text(String value, int size, int color) {
        TextView result = new TextView(this);
        result.setText(value);
        result.setTextSize(size);
        result.setTextColor(color);
        return result;
    }

    private TextView label(int title) {
        TextView result = text(getString(title), 16, ACCENT);
        result.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        return result;
    }

    private View step(String number, int title) {
        LinearLayout row = new LinearLayout(this);
        row.setGravity(Gravity.CENTER_VERTICAL);
        TextView badge = text(number, 12, ACCENT);
        badge.setGravity(Gravity.CENTER);
        badge.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        badge.setBackground(shape(TINT, 0, 11));
        row.addView(badge, new LinearLayout.LayoutParams(dp(34), dp(34)));
        TextView label = label(title);
        label.setTextColor(TEXT);
        LinearLayout.LayoutParams caption = new LinearLayout.LayoutParams(0, -2, 1);
        caption.leftMargin = dp(11);
        row.addView(label, caption);
        return row;
    }

    private GradientDrawable shape(int fill, int stroke, int radius) {
        GradientDrawable d = new GradientDrawable();
        d.setColor(fill);
        d.setCornerRadius(dp(radius));
        if (stroke != 0) d.setStroke(dp(1), stroke);
        return d;
    }

    private RadioButton choice(int title) {
        RadioButton radio = new RadioButton(this);
        radio.setId(View.generateViewId());
        radio.setText(title);
        radio.setTextColor(TEXT);
        radio.setTextSize(15);
        radio.setMinHeight(dp(56));
        StateListDrawable states = new StateListDrawable();
        states.addState(new int[]{android.R.attr.state_checked}, shape(TINT, 0xFFC5B7F4, 14));
        states.addState(new int[]{}, shape(0xFFFAF8FD, LINE, 14));
        radio.setBackground(new RippleDrawable(ColorStateList.valueOf(0x206146C5), states, null));
        radio.setPadding(dp(12), dp(6), dp(12), dp(6));
        RadioGroup.LayoutParams params = new RadioGroup.LayoutParams(-1, -2);
        params.topMargin = dp(6);
        radio.setLayoutParams(params);
        return radio;
    }

    private Button button(int title) { return button(title, TINT, ACCENT, LINE); }

    private Button button(int title, int fill, int ink, int border) {
        Button b = new Button(this);
        b.setText(title);
        b.setAllCaps(false);
        b.setGravity(Gravity.CENTER);
        b.setTextSize(15);
        b.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        b.setMinHeight(dp(50));
        b.setStateListAnimator(null);
        StateListDrawable states = new StateListDrawable();
        int[][] enabled = {{-android.R.attr.state_enabled}, {}};
        states.addState(enabled[0], shape(0xFFF0EDF4, LINE, 15));
        states.addState(enabled[1], shape(fill, border, 15));
        b.setTextColor(new ColorStateList(enabled, new int[]{0xFF746B80, ink}));
        b.setBackground(new RippleDrawable(ColorStateList.valueOf(0x296146C5), states, null));
        b.setPadding(dp(12), dp(10), dp(12), dp(10));
        return b;
    }

    private int dp(float value) {
        return Math.round(getResources().getDisplayMetrics().density * value);
    }

    private static String describe(Exception failure) {
        String message = failure.getMessage();
        if (message == null || message.trim().isEmpty()) return failure.getClass().getSimpleName();
        return message.length() <= 1800 ? message : message.substring(0, 1800) + "…";
    }

    /** Retained across recreation; worker threads hold only application context. */
    private static final class Session {
        private final Context context;
        private final Handler ui = new Handler(Looper.getMainLooper());
        private MainActivity view;
        private Porter porter;
        private Porter.Prepared prepared;
        private File pendingExport;
        private Uri vendorDocument;
        private Uri vbmetaDocument;
        private String model;
        private int statusId = R.string.idle;
        private String statusArg;
        private boolean busy;
        private boolean flashAllowed;
        private final StringBuilder messages = new StringBuilder();

        Session(Context context) { this.context = context; }
        void attach(MainActivity activity) { view = activity; changed(); }
        void detach(MainActivity activity) { if (view == activity) view = null; }
        void changed() { if (view != null) view.render(); }
        boolean blocked() { return busy || pendingExport != null; }
        boolean canFlash(Porter.Prepared p) {
            return p != null && prepared == p && flashAllowed && !blocked()
                    && vendorDocument != null && vbmetaDocument != null;
        }

        void setStatus(int id, String detail) {
            statusId = id;
            statusArg = detail;
            changed();
        }

        void note(String line) {
            if (line == null || line.isEmpty()) return;
            String shortLine = line.length() > 2048 ? line.substring(0, 2048) + "…" : line;
            ui.post(() -> {
                messages.append(shortLine).append('\n');
                int excess = messages.length() - 16000;
                if (excess > 0) {
                    int next = messages.indexOf("\n", excess);
                    messages.delete(0, next < 0 ? excess : next + 1);
                }
                changed();
            });
        }

        void prepare() {
            if (blocked()) return;
            String chosen = model;
            busy = true;
            flashAllowed = false;
            messages.setLength(0);
            setStatus(R.string.preparing, null);
            start("skyward-prepare", R.string.prepare_failed, () -> {
                Porter backend = new Porter(context);
                Porter.Prepared candidate = backend.prepare(chosen, this::note);
                if (candidate == null) throw new IOException("No prepared output");
                ui.post(() -> {
                    porter = backend;
                    prepared = candidate;
                    vendorDocument = null;
                    vbmetaDocument = null;
                    busy = false;
                    flashAllowed = true;
                    setStatus(R.string.ready, null);
                });
            });
        }

        void flash(Porter.Prepared p) {
            if (!canFlash(p)) return;
            Porter backend = porter;
            busy = true;
            // Never retry a potentially partial write using a stale candidate.
            flashAllowed = false;
            setStatus(R.string.flashing, null);
            start("skyward-flash", R.string.flash_failed, () -> {
                backend.flash(p, this::note);
                ui.post(() -> { busy = false; setStatus(R.string.flashed, null); });
            });
        }

        void exportBackup(File source, Uri destination) {
            if (blocked() || prepared == null) return;
            if (!"content".equals(destination.getScheme())) {
                setStatus(R.string.export_invalid_uri, null);
                return;
            }
            boolean vbmeta = source.equals(prepared.vbmetaBackup);
            if (!vbmeta && !source.equals(prepared.backup)) return;
            Uri other = vbmeta ? vendorDocument : vbmetaDocument;
            if (other != null && sameDocument(destination, other)) {
                setStatus(R.string.export_distinct, null);
                return;
            }
            // A failed repeat to the same destination might truncate it.
            if (vbmeta) vbmetaDocument = null;
            else vendorDocument = null;
            busy = true;
            setStatus(R.string.exporting, null);
            start("skyward-export", R.string.export_failed, () -> {
                long expected = source.length();
                if (expected <= 0) throw new IOException("The local backup is empty or unreadable");
                try (FileInputStream input = new FileInputStream(source);
                     OutputStream output = context.getContentResolver().openOutputStream(destination, "wt")) {
                    if (output == null) throw new IOException("The file provider did not open the destination");
                    byte[] buffer = new byte[128 * 1024];
                    long copied = 0;
                    for (int n; (n = input.read(buffer)) != -1; ) {
                        copied += n;
                        if (copied > expected) throw new IOException("The local backup changed");
                        output.write(buffer, 0, n);
                    }
                    if (copied != expected) throw new IOException("The local backup changed");
                    output.flush();
                }
                ui.post(() -> {
                    if (vbmeta) vbmetaDocument = destination;
                    else vendorDocument = destination;
                    busy = false;
                    setStatus(flashAllowed ? (canFlash(prepared) ? R.string.exported : R.string.export_one_left)
                            : R.string.exported_only, null);
                });
            });
        }

        private boolean sameDocument(Uri first, Uri second) {
            if (first.equals(second)) return true;
            if (first.getAuthority() == null || !first.getAuthority().equals(second.getAuthority())) return false;
            try {
                return android.provider.DocumentsContract.getDocumentId(first)
                        .equals(android.provider.DocumentsContract.getDocumentId(second));
            } catch (IllegalArgumentException ignored) {
                return false;
            }
        }

        private void start(String name, int errorStatus, Work work) {
            Thread thread = new Thread(() -> {
                try {
                    work.run();
                } catch (Exception failure) {
                    String message = describe(failure);
                    ui.post(() -> { busy = false; setStatus(errorStatus, message); });
                }
            }, name);
            try {
                thread.start();
            } catch (RuntimeException failure) {
                busy = false;
                setStatus(errorStatus, describe(failure));
            }
        }
    }

    private interface Work { void run() throws Exception; }
}
